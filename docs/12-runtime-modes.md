# Runtime Modes v1

Runtime modes control how Rygnal executes tool requests. Three safe execution modes are available.

## Modes

### OBSERVE Mode

**Purpose**: Monitor and audit without making any changes.

- Never executes any tools
- Logs all requests for review and analysis
- Useful for initial deployment, monitoring, and understanding tooling patterns
- Zero execution risk

**Behavior**:

```text
Tool request → Risk assessment → Policy decision → Audit log → SKIP (never execute)
```

### SIMULATE Mode

**Purpose**: Test policies in a safe, non-destructive environment.

- Applies policy rules to all requests
- Simulates execution but never runs actual tools
- Validates policy behavior before enforcement
- Helps identify issues before they affect production
- Low execution risk

**Behavior**:

```text
Tool request → Risk assessment → Policy decision → Audit log → SIMULATE (approved) or SKIP (denied)
```

### ENFORCE Mode

**Purpose**: Production operation with full policy enforcement.

- Fully enforces policies
- Executes tools approved by policy
- Blocks risky or rejected actions
- Requires approval for high-risk actions
- Integrated approval workflow support
- Highest security with full control

**Behavior**:

```text
Tool request → Risk assessment → Policy decision → [Approval if needed] → Audit log → EXECUTE (approved) or SKIP (denied)
```

## Safe Defaults

- **Default mode**: `ENFORCE`
- **Observe mode**: Always safe, never executes
- **Simulate mode**: Safe for testing, never executes actual tools
- **Enforce mode**: Respects policy decisions while maintaining audit trail

## Usage Example

```python
from rygnal.models import RuntimeMode
from rygnal.interceptor import RygnalInterceptor

# Start in OBSERVE mode to understand your environment
interceptor = RygnalInterceptor(
    policy_engine=policy_engine,
    audit_logger=audit_logger,
    tool_executor=executor,
    runtime_mode=RuntimeMode.OBSERVE,
)

# Progress to SIMULATE for safe testing
interceptor.runtime_mode = RuntimeMode.SIMULATE

# Deploy to ENFORCE for production operation
interceptor.runtime_mode = RuntimeMode.ENFORCE
```

## Migration Path

1. Deploy with `OBSERVE` mode to establish baseline
2. Review audit logs and policy effectiveness
3. Switch to `SIMULATE` mode for testing
4. Monitor simulated decisions for a period
5. Switch to `ENFORCE` mode for production

## Security Properties

All modes maintain:

- ✓ Complete audit trail for all requests
- ✓ Risk assessment for every tool action
- ✓ Policy evaluation before any execution (SIMULATE/ENFORCE)
- ✓ Tamper-evident audit events
- ✓ Approval workflow support (ENFORCE)
- ✓ No unsafe automatic execution
