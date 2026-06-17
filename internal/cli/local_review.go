package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
)

const (
	localReviewDirName = "rygnal"
	auditLogFileName   = "audit.jsonl"
	runsDirName        = "runs"
	summaryFileName    = "summary.json"
	patchFileName      = "patch.diff"
)

var safeRunIDPattern = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type localReviewStore struct {
	rootDir     string
	auditPath   string
	runsDir     string
	trustedRepo string
}

type runReviewRecord struct {
	RunID          string `json:"run_id"`
	RequestID      string `json:"request_id"`
	sortUnixNano   int64
	Status         string                        `json:"status"`
	Baseline       string                        `json:"baseline_commit_sha"`
	Backend        engineclient.BackendInfo      `json:"backend"`
	Command        engineclient.CommandInfo      `json:"command"`
	Changes        engineclient.ChangesInfo      `json:"changes"`
	Patch          engineclient.PatchInfo        `json:"patch"`
	Risk           engineclient.RiskInfo         `json:"risk"`
	Approval       engineclient.ApprovalInfo     `json:"approval"`
	BlockedReason  string                        `json:"blocked_reason"`
	Warnings       []string                      `json:"warnings"`
	Summary        engineclient.RunCompletedData `json:"summary"`
	PatchPath      string                        `json:"-"`
	SummaryPath    string                        `json:"-"`
	PatchDigest    string                        `json:"patch_digest,omitempty"`
	Apply          *localApplyRecord             `json:"apply,omitempty"`
	ArtifactSchema string                        `json:"artifact_schema"`
}

func newLocalReviewStore(repoRoot string) (localReviewStore, error) {
	gitDir, err := resolveAbsoluteGitDir(repoRoot)
	if err != nil {
		return localReviewStore{}, err
	}

	rootDir := filepath.Join(gitDir, localReviewDirName)

	return localReviewStore{
		rootDir:     rootDir,
		auditPath:   filepath.Join(rootDir, auditLogFileName),
		runsDir:     filepath.Join(rootDir, runsDirName),
		trustedRepo: repoRoot,
	}, nil
}

func resolveAbsoluteGitDir(repoRoot string) (string, error) {
	cmd := exec.Command("git", "-C", repoRoot, "rev-parse", "--absolute-git-dir")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve git metadata directory: %w", err)
	}

	gitDir := strings.TrimSpace(string(output))
	if gitDir == "" {
		return "", errors.New("resolve git metadata directory: empty path")
	}

	if !filepath.IsAbs(gitDir) {
		return "", fmt.Errorf("resolve git metadata directory: non-absolute path %q", gitDir)
	}

	return gitDir, nil
}

func (store localReviewStore) ensure() error {
	if err := os.MkdirAll(store.runsDir, 0o700); err != nil {
		return fmt.Errorf("create local review store: %w", err)
	}
	return nil
}

func (store localReviewStore) runDir(runID string) string {
	return filepath.Join(store.runsDir, safeRunID(runID))
}

func safeRunID(runID string) string {
	cleaned := strings.TrimSpace(runID)
	if cleaned == "" {
		return "unknown"
	}
	cleaned = safeRunIDPattern.ReplaceAllString(cleaned, "_")
	cleaned = strings.Trim(cleaned, "._-")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

func persistRunReviewArtifact(repoRoot string, requestID string, event *engineclient.EngineEvent) error {
	if event == nil {
		return nil
	}

	data, err := engineclient.DecodeRunCompletedData(*event)
	if err != nil {
		return err
	}

	runID := data.RunID
	if runID == "" {
		runID = requestID
	}
	if runID == "" {
		runID = event.RequestID
	}

	store, err := newLocalReviewStore(repoRoot)
	if err != nil {
		return err
	}
	if err := store.ensure(); err != nil {
		return err
	}

	runDir := store.runDir(runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return fmt.Errorf("create run review directory: %w", err)
	}

	rawPatch := data.Patch.Raw
	data.Patch.Raw = ""

	record := runReviewRecord{
		RunID:          runID,
		RequestID:      event.RequestID,
		Status:         data.Status,
		Baseline:       data.BaselineCommitSHA,
		Backend:        data.Backend,
		Command:        data.Command,
		Changes:        data.Changes,
		Patch:          data.Patch,
		Risk:           data.Risk,
		Approval:       data.Approval,
		BlockedReason:  data.BlockedReason,
		Warnings:       normalizeWarnings(data.Warnings),
		Summary:        data,
		ArtifactSchema: "rygnal.local_review.v1",
	}

	if data.Patch.Generated && rawPatch != "" {
		patchPath := filepath.Join(runDir, patchFileName)
		if err := os.WriteFile(patchPath, []byte(rawPatch), 0o600); err != nil {
			return fmt.Errorf("write run diff artifact: %w", err)
		}

		record.PatchPath = patchPath
		record.PatchDigest = sha256Hex(rawPatch)
	}

	summaryPath := filepath.Join(runDir, summaryFileName)
	record.SummaryPath = summaryPath

	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode run review summary: %w", err)
	}

	if err := os.WriteFile(summaryPath, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write run review summary: %w", err)
	}

	return nil
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func listRunReviewRecords(store localReviewStore) ([]runReviewRecord, error) {
	entries, err := os.ReadDir(store.runsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local review runs: %w", err)
	}

	records := make([]runReviewRecord, 0, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		summaryPath := filepath.Join(store.runsDir, entry.Name(), summaryFileName)
		record, err := readRunReviewRecord(summaryPath)
		if err != nil {
			continue
		}

		if info, err := os.Stat(summaryPath); err == nil {
			record.sortUnixNano = info.ModTime().UnixNano()
		}

		if record.SummaryPath == "" {
			record.SummaryPath = summaryPath
		}

		if record.PatchPath == "" {
			patchPath := filepath.Join(store.runsDir, entry.Name(), patchFileName)
			if _, err := os.Stat(patchPath); err == nil {
				record.PatchPath = patchPath
			}
		}

		if applyRecord, err := readLocalApplyRecord(filepath.Join(store.runsDir, entry.Name(), applyRecordFileName)); err == nil {
			record.Apply = &applyRecord
		}

		records = append(records, record)
	}

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].sortUnixNano != records[j].sortUnixNano {
			return records[i].sortUnixNano > records[j].sortUnixNano
		}
		return records[i].RunID > records[j].RunID
	})

	return records, nil
}

func readRunReviewRecord(path string) (runReviewRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return runReviewRecord{}, err
	}

	var record runReviewRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return runReviewRecord{}, fmt.Errorf("decode run review summary %s: %w", path, err)
	}

	return record, nil
}

func readLocalApplyRecord(path string) (localApplyRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return localApplyRecord{}, err
	}

	var record localApplyRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return localApplyRecord{}, fmt.Errorf("decode apply record %s: %w", path, err)
	}

	return record, nil
}

func latestRunReviewRecord(store localReviewStore) (runReviewRecord, error) {
	records, err := listRunReviewRecords(store)
	if err != nil {
		return runReviewRecord{}, err
	}

	if len(records) == 0 {
		return runReviewRecord{}, errors.New("no Rygnal audit runs found")
	}

	return records[0], nil
}

func findRunReviewRecord(store localReviewStore, runID string) (runReviewRecord, error) {
	if strings.TrimSpace(runID) == "" || runID == "latest" {
		return latestRunReviewRecord(store)
	}

	records, err := listRunReviewRecords(store)
	if err != nil {
		return runReviewRecord{}, err
	}

	for _, record := range records {
		if record.RunID == runID || strings.HasPrefix(record.RunID, runID) {
			return record, nil
		}
	}

	return runReviewRecord{}, fmt.Errorf("run %q not found", runID)
}
