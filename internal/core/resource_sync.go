package core

type syncOperation string

const (
	syncCreate syncOperation = "create"
	syncUpdate syncOperation = "update"
	syncDelete syncOperation = "delete"
	syncForget syncOperation = "forget"
)

// operation chooses the action when syncing a resource. Reconciliation also
// uses it for clean resources, so dirty admission belongs to the caller.
func (s ResourceSyncState) operation() syncOperation {
	switch {
	case s.Deleted && s.RemoteID == "":
		return syncForget
	case s.Deleted:
		return syncDelete
	case s.RemoteID == "":
		return syncCreate
	default:
		return syncUpdate
	}
}

func (o syncOperation) progressOperation() string {
	if o == syncForget {
		return "delete"
	}
	return string(o)
}

func (s ResourceSyncState) status() string {
	switch {
	case s.Deleted && s.Dirty:
		return "pending delete"
	case s.Deleted:
		return "deleted"
	case s.LastError != "":
		return "sync error"
	case !s.Dirty:
		return "synced"
	default:
		return "pending " + string(s.operation())
	}
}

func (s ResourceSyncState) pending(deleted bool) ResourceSyncState {
	s.Dirty = true
	s.Deleted = deleted
	s.LastError = ""
	return s
}

func (s ResourceSyncState) succeeded(remoteID string) ResourceSyncState {
	s.RemoteID = remoteID
	s.Dirty = false
	s.LastError = ""
	return s
}

func (s ResourceSyncState) failed(err error) ResourceSyncState {
	s.Dirty = true
	s.LastError = err.Error()
	return s
}

func (s ResourceSyncState) deletionSettled() bool {
	return s.Deleted && !s.Dirty && s.RemoteID == ""
}

func (u User) syncState() ResourceSyncState {
	return ResourceSyncState{RemoteID: u.RemoteID, Dirty: u.Dirty, Deleted: u.Deleted, LastError: u.LastError}
}

func (u *User) setSyncState(s ResourceSyncState) {
	u.RemoteID = s.RemoteID
	u.Dirty = s.Dirty
	u.Deleted = s.Deleted
	u.LastError = s.LastError
}

func (g Group) syncState() ResourceSyncState {
	return ResourceSyncState{RemoteID: g.RemoteID, Dirty: g.Dirty, Deleted: g.Deleted, LastError: g.LastError}
}

func (g *Group) setSyncState(s ResourceSyncState) {
	g.RemoteID = s.RemoteID
	g.Dirty = s.Dirty
	g.Deleted = s.Deleted
	g.LastError = s.LastError
}
