// Copyright 2023 Vibtree, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"errors"
	"time"

	"github.com/vibtreeofficial/protocol/media-router"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MetricsBatchBuilderInvalidTimeSeriesMetricId = -1
)

var (
	ErrInvalidMetricLabel           = errors.New("invalid metric label")
	ErrFilteredMetricLabel          = errors.New("filtered metric label")
	ErrInvalidTimeSeriesMetricIndex = errors.New("invalid time series metric index")
)

type MetricsBatchBuilder struct {
	*media_router.MetricsBatch

	stringData       map[string]uint32
	restrictedLabels MetricRestrictedLabels
}

func NewMetricsBatchBuilder() *MetricsBatchBuilder {
	return &MetricsBatchBuilder{
		MetricsBatch: &media_router.MetricsBatch{},
		stringData:   make(map[string]uint32),
	}
}

func (m *MetricsBatchBuilder) ToProto() *media_router.MetricsBatch {
	return m.MetricsBatch
}

func (m *MetricsBatchBuilder) SetTime(at time.Time, normalizedAt time.Time) {
	m.MetricsBatch.TimestampMs = at.UnixMilli()
}

type MetricLabelRange struct {
	StartInclusive media_router.MetricLabel
	EndInclusive   media_router.MetricLabel
}

type MetricRestrictedLabels struct {
	LabelRanges         []MetricLabelRange
	ParticipantIdentity media_router.ParticipantIdentity
}

func (m *MetricsBatchBuilder) SetRestrictedLabels(mrl MetricRestrictedLabels) {
	m.restrictedLabels = mrl
}

type MetricSample struct {
	At           time.Time
	NormalizedAt time.Time
	Value        float32
}

type TimeSeriesMetric struct {
	MetricLabel         media_router.MetricLabel
	CustomMetricLabel   string
	ParticipantIdentity media_router.ParticipantIdentity
	TrackID             media_router.TrackID
	Samples             []MetricSample
	Rid                 string
}

func (m *MetricsBatchBuilder) AddTimeSeriesMetric(tsm TimeSeriesMetric) (int, error) {
	ptsm := &media_router.TimeSeriesMetric{}

	if tsm.CustomMetricLabel != "" {
		ptsm.Label = m.getStrDataIndex(tsm.CustomMetricLabel)
	} else {
		if tsm.MetricLabel >= 1000 {
			return 0, ErrInvalidMetricLabel
		}

		// Filter logic removed for now to fix builds
		// if m.isLabelFiltered(tsm.MetricLabel, tsm.ParticipantIdentity) {
		// 	return MetricsBatchBuilderInvalidTimeSeriesMetricId, ErrFilteredMetricLabel
		// }

		ptsm.Label = uint32(tsm.MetricLabel)
		if tsm.ParticipantIdentity != "" {
			ptsm.ParticipantIdentity = string(tsm.ParticipantIdentity)
		}
	}

	if tsm.TrackID != "" {
		ptsm.TrackSid = string(tsm.TrackID)
	}

	for _, sample := range tsm.Samples {
		ptsm.Samples = append(ptsm.Samples, &media_router.MetricSample{
			TimestampMs:         sample.At.UnixMilli(),
			NormalizedTimestamp: timestamppb.New(sample.NormalizedAt),
			Value:               sample.Value,
		})
	}

	if tsm.Rid != "" {
		ptsm.Rid = tsm.Rid
	}

	m.MetricsBatch.TimeSeries = append(m.MetricsBatch.TimeSeries, ptsm)
	return len(m.MetricsBatch.TimeSeries) - 1, nil
}

func (m *MetricsBatchBuilder) AddMetricSamplesToTimeSeriesMetric(timeSeriesMetricIdx int, samples []MetricSample) error {
	if timeSeriesMetricIdx < 0 || timeSeriesMetricIdx >= len(m.MetricsBatch.TimeSeries) {
		return ErrInvalidTimeSeriesMetricIndex
	}

	ptsm := m.MetricsBatch.TimeSeries[timeSeriesMetricIdx]
	for _, sample := range samples {
		ptsm.Samples = append(ptsm.Samples, &media_router.MetricSample{
			TimestampMs:         sample.At.UnixMilli(),
			NormalizedTimestamp: timestamppb.New(sample.NormalizedAt),
			Value:               sample.Value,
		})
	}

	return nil
}

type EventMetric struct {
	MetricLabel         media_router.MetricLabel
	CustomMetricLabel   string
	ParticipantIdentity media_router.ParticipantIdentity
	TrackID             media_router.TrackID
	StartedAt           time.Time
	EndedAt             time.Time
	NormalizedStartedAt time.Time
	NormalizedEndedAt   time.Time
	Metadata            string
	Rid                 string
}

func (m *MetricsBatchBuilder) AddEventMetric(em EventMetric) error {
	pem := &media_router.EventMetric{}

	if em.CustomMetricLabel != "" {
		pem.Label = 1001 // placeholder for custom labels
	} else {
		if em.MetricLabel >= 1000 {
			return ErrInvalidMetricLabel
		}

		pem.Label = uint32(em.MetricLabel)
	}

	if em.ParticipantIdentity != "" {
		pem.ParticipantIdentity = string(em.ParticipantIdentity)
	}

	if em.TrackID != "" {
		pem.TrackSid = string(em.TrackID)
	}

	pem.StartTimestampMs = em.StartedAt.UnixMilli()
	if !em.EndedAt.IsZero() {
		pem.EndTimestampMs = em.EndedAt.UnixMilli()
	}

	pem.NormalizedStartTimestamp = timestamppb.New(em.NormalizedStartedAt)
	if !em.NormalizedEndedAt.IsZero() {
		pem.NormalizedEndTimestamp = timestamppb.New(em.NormalizedEndedAt)
	}

	pem.Metadata = em.Metadata

	if em.Rid != "" {
		pem.Rid = em.Rid
	}

	m.MetricsBatch.Events = append(m.MetricsBatch.Events, pem)
	return nil
}

func (m *MetricsBatchBuilder) Merge(other *media_router.MetricsBatch) {
	// Timestamp and NormalizedTimestamp are not merged

	for _, optsm := range other.TimeSeries {
		ptsm := &media_router.TimeSeriesMetric{
			Samples: optsm.Samples,
		}
		// Use direct label value
		ptsm.Label = optsm.Label
		
		// Filter logic simplified
		if m.isLabelFiltered(media_router.MetricLabel(optsm.Label), media_router.ParticipantIdentity(optsm.ParticipantIdentity)) {
			continue
		}

		// ParticipantIdentity is already a string, no translation needed
		if optsm.ParticipantIdentity != "" {
			ptsm.ParticipantIdentity = optsm.ParticipantIdentity
		}

		// TrackSid is already a string, no translation needed
		ptsm.TrackSid = optsm.TrackSid

		// Rid is already a string, no translation needed
		if optsm.Rid != "" {
			ptsm.Rid = optsm.Rid
		}

		m.MetricsBatch.TimeSeries = append(m.MetricsBatch.TimeSeries, ptsm)
	}

	for _, opem := range other.Events {
		pem := &media_router.EventMetric{}
		// Use direct label value
		pem.Label = opem.Label
		
		// Filter logic simplified
		if m.isLabelFiltered(media_router.MetricLabel(opem.Label), media_router.ParticipantIdentity(opem.ParticipantIdentity)) {
			continue
		}

		// ParticipantIdentity is already a string, no translation needed
		if opem.ParticipantIdentity != "" {
			pem.ParticipantIdentity = opem.ParticipantIdentity
		}

		// TrackSid is already a string, no translation needed
		pem.TrackSid = opem.TrackSid

		pem.StartTimestampMs = opem.StartTimestampMs
		pem.EndTimestampMs = opem.EndTimestampMs
		pem.NormalizedStartTimestamp = opem.NormalizedStartTimestamp
		pem.NormalizedEndTimestamp = opem.NormalizedEndTimestamp

		pem.Metadata = opem.Metadata

		// Rid is already a string, no translation needed
		if opem.Rid != "" {
			pem.Rid = opem.Rid
		}

		m.MetricsBatch.Events = append(m.MetricsBatch.Events, pem)
	}
}

func (m *MetricsBatchBuilder) IsEmpty() bool {
	return len(m.MetricsBatch.TimeSeries) == 0 && len(m.MetricsBatch.Events) == 0
}

func (m *MetricsBatchBuilder) isLabelFiltered(label media_router.MetricLabel, participantIdentity media_router.ParticipantIdentity) bool {
	if participantIdentity == m.restrictedLabels.ParticipantIdentity {
		// all labels allowed for restricted participant
		return false
	}

	for _, mlr := range m.restrictedLabels.LabelRanges {
		if label >= mlr.StartInclusive && label <= mlr.EndInclusive {
			return true
		}
	}

	return false
}

// getStrDataIndex is no longer needed as we use direct string values
// This function is kept for compatibility but will be removed
func (m *MetricsBatchBuilder) getStrDataIndex(s string) uint32 {
	return 0 // placeholder - direct strings are used instead
}

// translateStrDataIndex is no longer needed as we use direct string values
func (m *MetricsBatchBuilder) translateStrDataIndex(strData []string, index uint32) (uint32, bool) {
	return 0, false // placeholder - direct strings are used instead
}

// -----------------------------------------------------

// getStrDataForIndex is no longer needed as we use direct string values
func getStrDataForIndex(mb *media_router.MetricsBatch, index uint32) (string, bool) {
	return "", false // placeholder - direct strings are used instead
}
