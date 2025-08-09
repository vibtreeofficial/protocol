package agentsobs

import "github.com/vibtreeofficial/protocol/media-router"

func JobKindFromProto(kind media_router.JobType) JobKind {
	switch kind {
	case media_router.JobType_JT_ROOM:
		return JobKindRoom
	case media_router.JobType_JT_PUBLISHER:
		return JobKindPublisher
	case media_router.JobType_JT_PARTICIPANT:
		return JobKindParticipant
	default:
		return JobKindUndefined
	}
}

func JobStatusFromProto(status media_router.JobStatus) JobStatus {
	switch status {
	case media_router.JobStatus_JS_PENDING:
		return JobStatusPending
	case media_router.JobStatus_JS_RUNNING:
		return JobStatusRunning
	case media_router.JobStatus_JS_SUCCESS:
		return JobStatusSuccess
	case media_router.JobStatus_JS_FAILED:
		return JobStatusFailed
	default:
		return JobStatusUndefined
	}
}

func WorkerStatusFromProto(status media_router.WorkerStatus) WorkerStatus {
	switch status {
	case media_router.WorkerStatus_WS_AVAILABLE:
		return WorkerStatusAvailable
	case media_router.WorkerStatus_WS_FULL:
		return WorkerStatusFull
	default:
		return WorkerStatusUndefined
	}
}
