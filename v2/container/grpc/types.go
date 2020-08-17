package container

import (
	netmap "github.com/nspcc-dev/neofs-api-go/v2/netmap/grpc"
	refs "github.com/nspcc-dev/neofs-api-go/v2/refs/grpc"
	service "github.com/nspcc-dev/neofs-api-go/v2/service/grpc"
)

// SetKey sets key to the container attribute.
func (m *Container_Attribute) SetKey(v string) {
	if m != nil {
		m.Key = v
	}
}

// SetValue sets value of the container attribute.
func (m *Container_Attribute) SetValue(v string) {
	if m != nil {
		m.Value = v
	}
}

// SetOwnerId sets identifier of the container owner,
func (m *Container) SetOwnerId(v *refs.OwnerID) {
	if m != nil {
		m.OwnerId = v
	}
}

// SetNonce sets nonce of the container structure.
func (m *Container) SetNonce(v []byte) {
	if m != nil {
		m.Nonce = v
	}
}

// SetBasicAcl sets basic ACL of the container.
func (m *Container) SetBasicAcl(v uint32) {
	if m != nil {
		m.BasicAcl = v
	}
}

// SetAttributes sets list of the container attributes.
func (m *Container) SetAttributes(v []*Container_Attribute) {
	if m != nil {
		m.Attributes = v
	}
}

// SetPlacementPolicy sets placement policy of the container.
func (m *Container) SetPlacementPolicy(v *netmap.PlacementPolicy) {
	if m != nil {
		m.PlacementPolicy = v
	}
}

// SetVersion sets version of the container.
func (m *Container) SetVersion(v *service.Version) {
	if m != nil {
		m.Version = v
	}
}
