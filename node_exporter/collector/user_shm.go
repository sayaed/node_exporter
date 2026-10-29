//go:build linux && !nousershm
// +build linux,!nousershm

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	userShmSubsystem = "user_shm"

	// sysvipcShmFile is the kernel's own listing of SysV shared memory
	// segments: the same data `ipcs -m` prints, without the fork and the exec.
	sysvipcShmFile = "/proc/sysvipc/shm"

	// shmallFile holds the system-wide shared memory limit. Its unit is
	// *pages*, not bytes -- see readShmLimitBytes.
	shmallFile = "/proc/sys/kernel/shmall"
)

var userShmLabelNames = []string{"username", "env"}

type userShmLabels struct {
	username string
	env      string
}

type shmStat struct {
	labels userShmLabels
	size   float64
}

type userShmCollector struct {
	userDesc  *prometheus.Desc
	totalDesc *prometheus.Desc
	limitDesc *prometheus.Desc
	logger    *slog.Logger
}

func init() {
	registerCollector("usershm", defaultEnabled, NewUserShmCollector)
}

func NewUserShmCollector(logger *slog.Logger) (Collector, error) {
	userDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userShmSubsystem, "bytes"),
		"Total shared memory used by user (bytes)",
		userShmLabelNames, nil,
	)
	totalDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userShmSubsystem, "total_bytes"),
		"Total system shared memory usage (bytes)",
		nil, nil,
	)
	limitDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userShmSubsystem, "limit_bytes"),
		"Total system shared memory limit (bytes)",
		nil, nil,
	)
	return &userShmCollector{
		userDesc:  userDesc,
		totalDesc: totalDesc,
		limitDesc: limitDesc,
		logger:    logger,
	}, nil
}

func (c *userShmCollector) Update(ch chan<- prometheus.Metric) error {
	start := time.Now()
	stats, total, shmLimit, err := c.GetStats()
	duration := time.Since(start)

	// 记录收集持续时间（仅在调试模式下）
	c.logger.Debug("Shared memory collection completed", "duration", duration, "users_count", len(stats))

	if err != nil {
		return err
	}

	// 推送用户指标
	for _, s := range stats {
		ch <- prometheus.MustNewConstMetric(
			c.userDesc, prometheus.GaugeValue, s.size, s.labels.username, s.labels.env,
		)
	}

	// 推送总指标
	ch <- prometheus.MustNewConstMetric(
		c.totalDesc, prometheus.GaugeValue, float64(total),
	)

	// 推送共享内存限制指标 (仅当成功获取且大于0时)
	if shmLimit > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.limitDesc, prometheus.GaugeValue, shmLimit,
		)
	}
	return nil
}

func (c *userShmCollector) GetStats() ([]shmStat, int64, float64, error) {
	userUsageMap, total, err := c.parseSysvipcShm()
	if err != nil {
		return nil, 0, 0, err
	}

	// The environment tag is derived from the username string alone, so this
	// needs no process information at all.
	stats := make([]shmStat, 0, len(userUsageMap))
	for user, size := range userUsageMap {
		stats = append(stats, shmStat{
			labels: userShmLabels{
				username: user,
				env:      parseUserEnv(user),
			},
			size: float64(size),
		})
	}

	// Sorted so that the metric output is stable between scrapes; without it
	// the order follows Go's map iteration and changes on every gather.
	slices.SortFunc(stats, func(a, b shmStat) int {
		return strings.Compare(a.labels.username, b.labels.username)
	})

	shmLimit, err := c.readShmLimitBytes()
	if err != nil {
		// A missing limit must not take the per-user metrics down with it.
		c.logger.Error("Failed to read shared memory limit", "path", shmallFile, "error", err)
		return stats, total, 0, nil
	}

	return stats, total, shmLimit, nil
}

// parseSysvipcShm reads the SysV shared memory segments straight from the
// kernel, replacing `ipcs -m`.
//
// On top of dropping the fork and the 5s context wrapper that had to be built
// around it, this fixes a correctness problem: /proc/sysvipc/shm reports the
// owner as a numeric uid, which is then resolved through the ordinary
// /etc/passwd cache, whereas the old parser guessed whether the username was
// the 3rd or the 9th column based on how many fields a line happened to have
// and silently picked the wrong one when `ipcs` changed its output shape.
func (c *userShmCollector) parseSysvipcShm() (map[string]int64, int64, error) {
	f, err := os.Open(sysvipcShmFile)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open %s: %w", sysvipcShmFile, err)
	}
	defer f.Close()

	return parseSysvipcShmRows(f, lookupUsername)
}

// readShmLimitBytes returns the system-wide SysV shared memory limit in bytes.
//
// /proc/sys/kernel/shmall is expressed in *pages*: reading it as bytes is a
// factor of PAGE_SIZE off, and multiplying by 1024 (as the previous parser did
// with the kbytes figure `ipcs -m -l` prints) would be off by 1024/PAGE_SIZE.
// This is the quantity ipcs calls "max total shared memory".
func (c *userShmCollector) readShmLimitBytes() (float64, error) {
	raw, err := os.ReadFile(shmallFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", shmallFile, err)
	}

	pages, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse %s: %w", shmallFile, err)
	}

	return float64(pages) * float64(os.Getpagesize()), nil
}
