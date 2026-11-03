package sandboxes

import (
	"time"

	localv1 "github.com/lickren/sandboxes-api/gen/go/sandboxes/local/v1"
)

func fromProtoSandbox(in *localv1.Sandbox) (*Sandbox, error) {
	if in == nil {
		return nil, &Error{Code: errorCodeInternal, Message: "daemon returned an empty sandbox"}
	}
	if err := validateProtoSandbox(in); err != nil {
		return nil, err
	}
	return &Sandbox{
		ID:            in.GetId(),
		Name:          in.GetName(),
		State:         sandboxState(in.GetState()),
		Generation:    in.GetGeneration(),
		Image:         in.GetImage(),
		Workspace:     in.GetWorkspace(),
		Workspaces:    fromProtoWorkspaces(in.GetWorkspaces()),
		Ports:         fromProtoPorts(in.GetPorts()),
		Allow:         fromProtoRules(in.GetAllow()),
		Deny:          fromProtoRules(in.GetDeny()),
		Agent:         in.GetAgent(),
		Detached:      in.GetDetached(),
		PolicyProfile: in.GetPolicyProfile(),
		LastUsedAt:    protoLastUsed(in),
		CPUs:          in.GetCpus(),
		MemoryMiB:     in.GetMemoryMib(),
		StoppedAt:     unixTime(in.GetStoppedAtUnix()),
		Error:         in.GetError(),
		CreatedAt:     unixTime(in.GetCreatedAtUnix()),
		UpdatedAt:     unixTime(in.GetUpdatedAtUnix()),
	}, nil
}

func validateProtoSandbox(in *localv1.Sandbox) error {
	for _, port := range in.GetPorts() {
		if port == nil || port.GetHost() > 65535 || port.GetGuest() > 65535 {
			return &Error{Code: errorCodeInternal, Message: "invalid port in daemon response"}
		}
	}
	for _, rules := range [][]*localv1.NetworkRule{in.GetAllow(), in.GetDeny()} {
		for _, rule := range rules {
			if rule == nil || rule.GetPort() > 65535 {
				return &Error{Code: errorCodeInternal, Message: "invalid network rule in daemon response"}
			}
		}
	}
	return nil
}

func protoLastUsed(in *localv1.Sandbox) time.Time {
	if nano := in.GetLastUsedAtUnixNano(); nano != 0 {
		return time.Unix(0, nano).UTC()
	}
	return unixTime(in.GetLastUsedAtUnix())
}

func fromProtoOperation(in *localv1.Operation) *Operation {
	if in == nil {
		return nil
	}
	return &Operation{
		ID:         in.GetId(),
		SandboxID:  in.GetSandboxId(),
		Kind:       operationKind(in.GetKind()),
		State:      operationState(in.GetState()),
		Generation: in.GetGeneration(),
		Error:      in.GetError(),
		CreatedAt:  unixTime(in.GetCreatedAtUnix()),
		UpdatedAt:  unixTime(in.GetUpdatedAtUnix()),
	}
}

func fromProtoEvent(in *localv1.WatchResponse) (*Event, error) {
	if in == nil {
		return nil, &Error{Code: errorCodeInternal, Message: "daemon returned an empty event"}
	}
	var sb *Sandbox
	if in.GetSandbox() != nil {
		var err error
		sb, err = fromProtoSandbox(in.GetSandbox())
		if err != nil {
			return nil, err
		}
	}
	return &Event{
		Type:      in.GetType(),
		Sandbox:   sb,
		Operation: fromProtoOperation(in.GetOperation()),
		Revision:  in.GetRevision(),
	}, nil
}

func unixTime(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}

func sandboxState(v localv1.SandboxState) string {
	switch v {
	case localv1.SandboxState_SANDBOX_STATE_PENDING:
		return StatePending
	case localv1.SandboxState_SANDBOX_STATE_CREATING:
		return StateCreating
	case localv1.SandboxState_SANDBOX_STATE_RUNNING:
		return StateRunning
	case localv1.SandboxState_SANDBOX_STATE_STOPPING:
		return StateStopping
	case localv1.SandboxState_SANDBOX_STATE_STOPPED:
		return StateStopped
	case localv1.SandboxState_SANDBOX_STATE_DELETING:
		return StateDeleting
	case localv1.SandboxState_SANDBOX_STATE_DELETED:
		return StateDeleted
	case localv1.SandboxState_SANDBOX_STATE_FAILED:
		return StateFailed
	default:
		return StateUnknown
	}
}

func operationKind(v localv1.OperationKind) string {
	switch v {
	case localv1.OperationKind_OPERATION_KIND_CREATE:
		return "create"
	case localv1.OperationKind_OPERATION_KIND_START:
		return "start"
	case localv1.OperationKind_OPERATION_KIND_STOP:
		return "stop"
	case localv1.OperationKind_OPERATION_KIND_DELETE:
		return "delete"
	default:
		return StateUnknown
	}
}

func operationState(v localv1.OperationState) string {
	switch v {
	case localv1.OperationState_OPERATION_STATE_PENDING:
		return StatePending
	case localv1.OperationState_OPERATION_STATE_RUNNING:
		return StateRunning
	case localv1.OperationState_OPERATION_STATE_DONE:
		return StateDone
	case localv1.OperationState_OPERATION_STATE_FAILED:
		return StateFailed
	default:
		return StateUnknown
	}
}

func toProtoWorkspaces(workspaces []Workspace) []*localv1.Workspace {
	out := make([]*localv1.Workspace, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, &localv1.Workspace{Path: workspaces[i].Path, ReadOnly: workspaces[i].ReadOnly})
	}
	return out
}

func fromProtoWorkspaces(workspaces []*localv1.Workspace) []Workspace {
	out := make([]Workspace, 0, len(workspaces))
	for _, workspace := range workspaces {
		if workspace == nil {
			continue
		}
		out = append(out, Workspace{Path: workspace.GetPath(), ReadOnly: workspace.GetReadOnly()})
	}
	return out
}

func toProtoPorts(ports []Port) []*localv1.Port {
	out := make([]*localv1.Port, 0, len(ports))
	for i := range ports {
		out = append(out, &localv1.Port{Host: uint32(ports[i].Host), Guest: uint32(ports[i].Guest), Protocol: ports[i].Protocol, HostIp: ports[i].HostIP})
	}
	return out
}

func fromProtoPorts(ports []*localv1.Port) []Port {
	out := make([]Port, 0, len(ports))
	for _, port := range ports {
		if port == nil || port.GetHost() > 65535 || port.GetGuest() > 65535 {
			continue
		}
		out = append(out, Port{Host: uint16(port.GetHost()), Guest: uint16(port.GetGuest()), Protocol: port.GetProtocol(), HostIP: port.GetHostIp()}) // #nosec G115 -- both values are bounded above
	}
	return out
}

func toProtoRules(rules []NetworkRule) []*localv1.NetworkRule {
	out := make([]*localv1.NetworkRule, 0, len(rules))
	for i := range rules {
		out = append(out, &localv1.NetworkRule{Protocol: rules[i].Protocol, Cidr: rules[i].CIDR, Port: uint32(rules[i].Port), Domain: rules[i].Domain, RuleId: rules[i].RuleID})
	}
	return out
}

func fromProtoRules(rules []*localv1.NetworkRule) []NetworkRule {
	out := make([]NetworkRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil || rule.GetPort() > 65535 {
			continue
		}
		out = append(out, NetworkRule{Protocol: rule.GetProtocol(), CIDR: rule.GetCidr(), Port: uint16(rule.GetPort()), Domain: rule.GetDomain(), RuleID: rule.GetRuleId()}) // #nosec G115 -- port is bounded above
	}
	return out
}
