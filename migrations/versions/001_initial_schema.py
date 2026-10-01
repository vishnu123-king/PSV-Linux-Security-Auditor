"""Initial PSV Auditor Schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-01 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Organizations
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=128), nullable=False, unique=True),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('full_name', sa.String(length=128), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
    )

    # Credential References
    op.create_table(
        'credential_references',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('auth_type', sa.String(length=32), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('encrypted_secret', sa.Text(), nullable=False),
        sa.Column('key_passphrase', sa.Text(), nullable=True),
        sa.Column('fingerprint', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Hosts
    op.create_table(
        'hosts',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('credential_id', sa.String(length=36), sa.ForeignKey('credential_references.id', ondelete='SET NULL'), nullable=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False, default=22),
        sa.Column('environment', sa.String(length=32), nullable=False, default='production'),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('os_family', sa.String(length=64), nullable=True),
        sa.Column('os_distribution', sa.String(length=64), nullable=True),
        sa.Column('os_version', sa.String(length=64), nullable=True),
        sa.Column('kernel_version', sa.String(length=128), nullable=True),
        sa.Column('arch', sa.String(length=32), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_assessment_status', sa.String(length=32), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Profiles
    op.create_table(
        'profiles',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('is_system_default', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Rules
    op.create_table(
        'rules',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('control', sa.String(length=128), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('condition', sa.JSON(), nullable=False),
        sa.Column('remediation_guidance', sa.Text(), nullable=False),
        sa.Column('verification_method', sa.Text(), nullable=False),
        sa.Column('supported_distros', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Assessments
    op.create_table(
        'assessments',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('host_id', sa.String(length=36), sa.ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', sa.String(length=64), sa.ForeignKey('profiles.id'), nullable=False),
        sa.Column('triggered_by', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('progress_percent', sa.Integer(), nullable=False, default=0),
        sa.Column('current_collector', sa.String(length=64), nullable=True),
        sa.Column('completed_collectors', sa.JSON(), nullable=False),
        sa.Column('total_rules', sa.Integer(), nullable=False, default=0),
        sa.Column('passed_rules', sa.Integer(), nullable=False, default=0),
        sa.Column('failed_rules', sa.Integer(), nullable=False, default=0),
        sa.Column('warn_rules', sa.Integer(), nullable=False, default=0),
        sa.Column('unknown_rules', sa.Integer(), nullable=False, default=0),
        sa.Column('critical_count', sa.Integer(), nullable=False, default=0),
        sa.Column('high_count', sa.Integer(), nullable=False, default=0),
        sa.Column('medium_count', sa.Integer(), nullable=False, default=0),
        sa.Column('low_count', sa.Integer(), nullable=False, default=0),
        sa.Column('compliance_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Observations
    op.create_table(
        'observations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('assessment_id', sa.String(length=36), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('collector', sa.String(length=64), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('control', sa.String(length=128), nullable=False),
        sa.Column('value', sa.JSON(), nullable=True),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('command_executed', sa.String(length=255), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('assessment_id', sa.String(length=36), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('host_id', sa.String(length=36), sa.ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('rule_id', sa.String(length=64), sa.ForeignKey('rules.id'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('result', sa.String(length=32), nullable=False),
        sa.Column('control', sa.String(length=128), nullable=False),
        sa.Column('expected_value', sa.JSON(), nullable=True),
        sa.Column('actual_value', sa.JSON(), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('remediation_guidance', sa.Text(), nullable=False),
        sa.Column('verification_method', sa.Text(), nullable=False),
        sa.Column('acknowledged_by', sa.String(length=64), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('suppressed_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Evidence
    op.create_table(
        'evidences',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('finding_id', sa.String(length=36), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_file', sa.String(length=255), nullable=True),
        sa.Column('command_executed', sa.String(length=255), nullable=True),
        sa.Column('raw_output', sa.Text(), nullable=False),
        sa.Column('normalized_data', sa.JSON(), nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Remediation
    op.create_table(
        'remediations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('finding_id', sa.String(length=36), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('target_file', sa.String(length=255), nullable=True),
        sa.Column('proposed_diff', sa.Text(), nullable=True),
        sa.Column('commands', sa.JSON(), nullable=False),
        sa.Column('backup_path', sa.String(length=255), nullable=True),
        sa.Column('rollback_commands', sa.JSON(), nullable=False),
        sa.Column('approved_by', sa.String(length=64), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('execution_output', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Verification
    op.create_table(
        'verifications',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('finding_id', sa.String(length=36), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('command_used', sa.String(length=255), nullable=False),
        sa.Column('output', sa.Text(), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Reports
    op.create_table(
        'reports',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('assessment_id', sa.String(length=36), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('format', sa.String(length=16), nullable=False),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Audit Events
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False),
        sa.Column('resource_id', sa.String(length=64), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('reports')
    op.drop_table('verifications')
    op.drop_table('remediations')
    op.drop_table('evidences')
    op.drop_table('findings')
    op.drop_table('observations')
    op.drop_table('assessments')
    op.drop_table('rules')
    op.drop_table('profiles')
    op.drop_table('hosts')
    op.drop_table('credential_references')
    op.drop_table('users')
    op.drop_table('organizations')
