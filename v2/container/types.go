package container

import (
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/netmap"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-api-go/v2/session"
)

type Attribute struct {
	key, val string
}

type Container struct {
	version *refs.Version

	ownerID *refs.OwnerID

	nonce []byte

	basicACL uint32

	attr []*Attribute

	policy *netmap.PlacementPolicy
}

type PutRequestBody struct {
	cnr *Container

	sig *refs.Signature
}
type PutRequest struct {
	body *PutRequestBody

	session.RequestHeaders
}

type PutResponseBody struct {
	cid *refs.ContainerID
}

type PutResponse struct {
	body *PutResponseBody

	session.ResponseHeaders
}

type GetRequestBody struct {
	cid *refs.ContainerID
}

type GetRequest struct {
	body *GetRequestBody

	session.RequestHeaders
}

type GetResponseBody struct {
	cnr *Container

	token *session.SessionToken

	sig *refs.Signature
}

type GetResponse struct {
	body *GetResponseBody

	session.ResponseHeaders
}

type DeleteRequestBody struct {
	cid *refs.ContainerID

	sig *refs.Signature
}

type DeleteRequest struct {
	body *DeleteRequestBody

	session.RequestHeaders
}

type DeleteResponseBody struct{}

type DeleteResponse struct {
	body *DeleteResponseBody

	session.ResponseHeaders
}

type ListRequestBody struct {
	ownerID *refs.OwnerID
}

type ListRequest struct {
	body *ListRequestBody

	session.RequestHeaders
}

type ListResponseBody struct {
	cidList []*refs.ContainerID
}

type ListResponse struct {
	body *ListResponseBody

	session.ResponseHeaders
}

type SetExtendedACLRequestBody struct {
	eacl *acl.Table

	sig *refs.Signature
}

type SetExtendedACLRequest struct {
	body *SetExtendedACLRequestBody

	session.RequestHeaders
}

type SetExtendedACLResponseBody struct{}

type SetExtendedACLResponse struct {
	body *SetExtendedACLResponseBody

	session.ResponseHeaders
}

type GetExtendedACLRequestBody struct {
	cid *refs.ContainerID
}

type GetExtendedACLRequest struct {
	body *GetExtendedACLRequestBody

	session.RequestHeaders
}

type GetExtendedACLResponseBody struct {
	eacl *acl.Table

	sig *refs.Signature

	token *session.SessionToken
}

type GetExtendedACLResponse struct {
	body *GetExtendedACLResponseBody

	session.ResponseHeaders
}

type UsedSpaceAnnouncement struct {
	epoch uint64

	cid *refs.ContainerID

	usedSpace uint64
}

type AnnounceUsedSpaceRequestBody struct {
	announcements []*UsedSpaceAnnouncement
}

type AnnounceUsedSpaceRequest struct {
	body *AnnounceUsedSpaceRequestBody

	session.RequestHeaders
}

type AnnounceUsedSpaceResponseBody struct{}

type AnnounceUsedSpaceResponse struct {
	body *AnnounceUsedSpaceResponseBody

	session.ResponseHeaders
}

func (a *Attribute) GetKey() string {
	if a != nil {
		return a.key
	}

	return ""
}

func (a *Attribute) SetKey(v string) {
	if a != nil {
		a.key = v
	}
}

func (a *Attribute) GetValue() string {
	if a != nil {
		return a.val
	}

	return ""
}

func (a *Attribute) SetValue(v string) {
	if a != nil {
		a.val = v
	}
}

func (c *Container) GetVersion() *refs.Version {
	if c != nil {
		return c.version
	}

	return nil
}

func (c *Container) SetVersion(v *refs.Version) {
	if c != nil {
		c.version = v
	}
}

func (c *Container) GetOwnerID() *refs.OwnerID {
	if c != nil {
		return c.ownerID
	}

	return nil
}

func (c *Container) SetOwnerID(v *refs.OwnerID) {
	if c != nil {
		c.ownerID = v
	}
}

func (c *Container) GetNonce() []byte {
	if c != nil {
		return c.nonce
	}

	return nil
}

func (c *Container) SetNonce(v []byte) {
	if c != nil {
		c.nonce = v
	}
}

func (c *Container) GetBasicACL() uint32 {
	if c != nil {
		return c.basicACL
	}

	return 0
}

func (c *Container) SetBasicACL(v uint32) {
	if c != nil {
		c.basicACL = v
	}
}

func (c *Container) GetAttributes() []*Attribute {
	if c != nil {
		return c.attr
	}

	return nil
}

func (c *Container) SetAttributes(v []*Attribute) {
	if c != nil {
		c.attr = v
	}
}

func (c *Container) GetPlacementPolicy() *netmap.PlacementPolicy {
	if c != nil {
		return c.policy
	}

	return nil
}

func (c *Container) SetPlacementPolicy(v *netmap.PlacementPolicy) {
	if c != nil {
		c.policy = v
	}
}

func (r *PutRequestBody) GetContainer() *Container {
	if r != nil {
		return r.cnr
	}

	return nil
}

func (r *PutRequestBody) SetContainer(v *Container) {
	if r != nil {
		r.cnr = v
	}
}

func (r *PutRequestBody) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

func (r *PutRequestBody) SetSignature(v *refs.Signature) {
	if r != nil {
		r.sig = v
	}
}

func (r *PutRequest) GetBody() *PutRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *PutRequest) SetBody(v *PutRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *PutResponseBody) GetContainerID() *refs.ContainerID {
	if r != nil {
		return r.cid
	}

	return nil
}

func (r *PutResponseBody) SetContainerID(v *refs.ContainerID) {
	if r != nil {
		r.cid = v
	}
}

func (r *PutResponse) GetBody() *PutResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *PutResponse) SetBody(v *PutResponseBody) {
	if r != nil {
		r.body = v
	}
}

func (r *GetRequestBody) GetContainerID() *refs.ContainerID {
	if r != nil {
		return r.cid
	}

	return nil
}

func (r *GetRequestBody) SetContainerID(v *refs.ContainerID) {
	if r != nil {
		r.cid = v
	}
}

func (r *GetRequest) GetBody() *GetRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetRequest) SetBody(v *GetRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *GetResponseBody) GetContainer() *Container {
	if r != nil {
		return r.cnr
	}

	return nil
}

func (r *GetResponseBody) SetContainer(v *Container) {
	if r != nil {
		r.cnr = v
	}
}

// GetSessionToken returns token of the session within which requested
// container was created.
func (r *GetResponseBody) GetSessionToken() *session.SessionToken {
	if r != nil {
		return r.token
	}

	return nil
}

// SetSessionToken sets token of the session within which requested
// container was created.
func (r *GetResponseBody) SetSessionToken(v *session.SessionToken) {
	if r != nil {
		r.token = v
	}
}

// GetSignature returns signature of the requested container.
func (r *GetResponseBody) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

// SetSignature sets signature of the requested container.
func (r *GetResponseBody) SetSignature(v *refs.Signature) {
	if r != nil {
		r.sig = v
	}
}

func (r *GetResponse) GetBody() *GetResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetResponse) SetBody(v *GetResponseBody) {
	if r != nil {
		r.body = v
	}
}

func (r *DeleteRequestBody) GetContainerID() *refs.ContainerID {
	if r != nil {
		return r.cid
	}

	return nil
}

func (r *DeleteRequestBody) SetContainerID(v *refs.ContainerID) {
	if r != nil {
		r.cid = v
	}
}

func (r *DeleteRequestBody) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

func (r *DeleteRequestBody) SetSignature(v *refs.Signature) {
	if r != nil {
		r.sig = v
	}
}

func (r *DeleteRequest) GetBody() *DeleteRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *DeleteRequest) SetBody(v *DeleteRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *DeleteResponse) GetBody() *DeleteResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *DeleteResponse) SetBody(v *DeleteResponseBody) {
	if r != nil {
		r.body = v
	}
}

func (r *ListRequestBody) GetOwnerID() *refs.OwnerID {
	if r != nil {
		return r.ownerID
	}

	return nil
}

func (r *ListRequestBody) SetOwnerID(v *refs.OwnerID) {
	if r != nil {
		r.ownerID = v
	}
}

func (r *ListRequest) GetBody() *ListRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *ListRequest) SetBody(v *ListRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *ListResponseBody) GetContainerIDs() []*refs.ContainerID {
	if r != nil {
		return r.cidList
	}

	return nil
}

func (r *ListResponseBody) SetContainerIDs(v []*refs.ContainerID) {
	if r != nil {
		r.cidList = v
	}
}

func (r *ListResponse) GetBody() *ListResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *ListResponse) SetBody(v *ListResponseBody) {
	if r != nil {
		r.body = v
	}
}

func (r *SetExtendedACLRequestBody) GetEACL() *acl.Table {
	if r != nil {
		return r.eacl
	}

	return nil
}

func (r *SetExtendedACLRequestBody) SetEACL(v *acl.Table) {
	if r != nil {
		r.eacl = v
	}
}

func (r *SetExtendedACLRequestBody) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

func (r *SetExtendedACLRequestBody) SetSignature(v *refs.Signature) {
	if r != nil {
		r.sig = v
	}
}

func (r *SetExtendedACLRequest) GetBody() *SetExtendedACLRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *SetExtendedACLRequest) SetBody(v *SetExtendedACLRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *SetExtendedACLResponse) GetBody() *SetExtendedACLResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *SetExtendedACLResponse) SetBody(v *SetExtendedACLResponseBody) {
	if r != nil {
		r.body = v
	}
}

func (r *GetExtendedACLRequestBody) GetContainerID() *refs.ContainerID {
	if r != nil {
		return r.cid
	}

	return nil
}

func (r *GetExtendedACLRequestBody) SetContainerID(v *refs.ContainerID) {
	if r != nil {
		r.cid = v
	}
}

func (r *GetExtendedACLRequest) GetBody() *GetExtendedACLRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetExtendedACLRequest) SetBody(v *GetExtendedACLRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *GetExtendedACLResponseBody) GetEACL() *acl.Table {
	if r != nil {
		return r.eacl
	}

	return nil
}

func (r *GetExtendedACLResponseBody) SetEACL(v *acl.Table) {
	if r != nil {
		r.eacl = v
	}
}

func (r *GetExtendedACLResponseBody) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

func (r *GetExtendedACLResponseBody) SetSignature(v *refs.Signature) {
	if r != nil {
		r.sig = v
	}
}

// GetSessionToken returns token of the session within which requested
// eACL table was set.
func (r *GetExtendedACLResponseBody) GetSessionToken() *session.SessionToken {
	if r != nil {
		return r.token
	}

	return nil
}

// SetSessionToken sets token of the session within which requested
// eACL table was set.
func (r *GetExtendedACLResponseBody) SetSessionToken(v *session.SessionToken) {
	if r != nil {
		r.token = v
	}
}

func (r *GetExtendedACLResponse) GetBody() *GetExtendedACLResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetExtendedACLResponse) SetBody(v *GetExtendedACLResponseBody) {
	if r != nil {
		r.body = v
	}
}

func (a *UsedSpaceAnnouncement) GetEpoch() uint64 {
	if a != nil {
		return a.epoch
	}

	return 0
}

func (a *UsedSpaceAnnouncement) SetEpoch(v uint64) {
	if a != nil {
		a.epoch = v
	}
}

func (a *UsedSpaceAnnouncement) GetUsedSpace() uint64 {
	if a != nil {
		return a.usedSpace
	}

	return 0
}

func (a *UsedSpaceAnnouncement) SetUsedSpace(v uint64) {
	if a != nil {
		a.usedSpace = v
	}
}

func (a *UsedSpaceAnnouncement) GetContainerID() *refs.ContainerID {
	if a != nil {
		return a.cid
	}

	return nil
}

func (a *UsedSpaceAnnouncement) SetContainerID(v *refs.ContainerID) {
	if a != nil {
		a.cid = v
	}
}

func (r *AnnounceUsedSpaceRequestBody) GetAnnouncements() []*UsedSpaceAnnouncement {
	if r != nil {
		return r.announcements
	}

	return nil
}

func (r *AnnounceUsedSpaceRequestBody) SetAnnouncements(v []*UsedSpaceAnnouncement) {
	if r != nil {
		r.announcements = v
	}
}

func (r *AnnounceUsedSpaceRequest) GetBody() *AnnounceUsedSpaceRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *AnnounceUsedSpaceRequest) SetBody(v *AnnounceUsedSpaceRequestBody) {
	if r != nil {
		r.body = v
	}
}

func (r *AnnounceUsedSpaceResponse) GetBody() *AnnounceUsedSpaceResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *AnnounceUsedSpaceResponse) SetBody(v *AnnounceUsedSpaceResponseBody) {
	if r != nil {
		r.body = v
	}
}
