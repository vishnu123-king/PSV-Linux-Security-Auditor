import asyncio
import json
import logging
from typing import Any, Callable, Dict, Optional
import aio_pika
from backend.app.core.config import get_settings

logger = logging.getLogger(__name__)


class EventBus:
    """
    Dual-mode message broker supporting production RabbitMQ (aio-pika)
    and zero-dependency in-process asyncio queues for development and testing.
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        self._connection: Optional[aio_pika.RobustConnection] = None
        self._channel: Optional[aio_pika.RobustChannel] = None
        self._memory_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self._is_memory_mode: bool = self.settings.RABBITMQ_URL.startswith("memory://")
        self._consumers: list[Callable[[Dict[str, Any]], Any]] = []
        self._consumer_task: Optional[asyncio.Task[None]] = None

    async def connect(self) -> None:
        if self._is_memory_mode:
            logger.info("EventBus initialized in in-memory mode (RABBITMQ_URL=memory://)")
            self._consumer_task = asyncio.create_task(self._process_memory_queue())
            return

        try:
            logger.info(f"Connecting to RabbitMQ broker at {self.settings.RABBITMQ_URL}...")
            self._connection = await aio_pika.connect_robust(
                self.settings.RABBITMQ_URL,
                timeout=5.0
            )
            self._channel = await self._connection.channel()
            await self._channel.set_qos(prefetch_count=self.settings.MAX_CONCURRENT_ASSESSMENTS)

            # Declare assessment queue with dead letter exchange
            await self._channel.declare_queue(
                self.settings.RABBITMQ_QUEUE_NAME,
                durable=True
            )
            logger.info("Successfully connected to RabbitMQ broker.")
        except Exception as e:
            logger.warning(
                f"Failed to connect to RabbitMQ ({e}). Falling back to local in-memory event bus."
            )
            self._is_memory_mode = True
            self._consumer_task = asyncio.create_task(self._process_memory_queue())

    async def publish_assessment_job(self, assessment_id: str, host_id: str, profile_id: str) -> None:
        payload = {
            "type": "assessment.run",
            "assessment_id": assessment_id,
            "host_id": host_id,
            "profile_id": profile_id
        }

        if self._is_memory_mode or not self._channel:
            await self._memory_queue.put(payload)
            logger.info(f"Enqueued assessment job {assessment_id} in local memory queue.")
            return

        try:
            message = aio_pika.Message(
                body=json.dumps(payload).encode("utf-8"),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                content_type="application/json"
            )
            await self._channel.default_exchange.publish(
                message,
                routing_key=self.settings.RABBITMQ_QUEUE_NAME
            )
            logger.info(f"Published assessment job {assessment_id} to RabbitMQ queue {self.settings.RABBITMQ_QUEUE_NAME}.")
        except Exception as e:
            logger.error(f"Failed to publish to RabbitMQ, enqueuing locally: {e}")
            await self._memory_queue.put(payload)

    def register_consumer(self, callback: Callable[[Dict[str, Any]], Any]) -> None:
        self._consumers.append(callback)

    async def _process_memory_queue(self) -> None:
        while True:
            try:
                job = await self._memory_queue.get()
                for consumer in self._consumers:
                    try:
                        res = consumer(job)
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception as err:
                        logger.error(f"Consumer execution error for job {job}: {err}")
                self._memory_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing memory queue: {e}")
                await asyncio.sleep(1)

    async def close(self) -> None:
        if self._consumer_task:
            self._consumer_task.cancel()
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
            logger.info("Closed RabbitMQ connection.")


event_bus = EventBus()
