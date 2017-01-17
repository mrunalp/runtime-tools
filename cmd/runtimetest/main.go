package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/mndrix/tap-go"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/cmd/runtimetest/mount"
	"github.com/syndtr/gocapability/capability"
	"github.com/urfave/cli"
)

// PR_GET_NO_NEW_PRIVS isn't exposed in Golang so we define it ourselves copying the value from
// the kernel
const PR_GET_NO_NEW_PRIVS = 39

const specConfig = "config.json"

var (
	defaultFS = map[string]string{
		"/proc":    "proc",
		"/sys":     "sysfs",
		"/dev/pts": "devpts",
		"/dev/shm": "tmpfs",
	}

	defaultSymlinks = map[string]string{
		"/dev/fd":     "/proc/self/fd",
		"/dev/stdin":  "/proc/self/fd/0",
		"/dev/stdout": "/proc/self/fd/1",
		"/dev/stderr": "/proc/self/fd/2",
	}

	defaultDevices = []string{
		"/dev/null",
		"/dev/zero",
		"/dev/full",
		"/dev/random",
		"/dev/urandom",
		"/dev/tty",
		"/dev/ptmx",
	}
)

type validator func(harness *tap.T, config *rspec.Spec) (err error)

func loadSpecConfig() (spec *rspec.Spec, err error) {
	cf, err := os.Open(specConfig)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found", specConfig)
		}
	}
	defer cf.Close()

	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return
	}
	return spec, nil
}

// should be included by other platform specified process validation
func validateGeneralProcess(harness *tap.T, spec *rspec.Spec) error {
	if spec.Process.Cwd == "" {
		harness.Skip(1, "process.cwd not set")
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		harness.Ok(cwd == spec.Process.Cwd, "has expected working directory")
		if cwd != spec.Process.Cwd {
			harness.Diagnosticf("working directory expected: %v, actual: %v", spec.Process.Cwd, cwd)
		}
	}

	for _, env := range spec.Process.Env {
		parts := strings.Split(env, "=")
		key := parts[0]
		expectedValue := parts[1]
		actualValue := os.Getenv(key)
		harness.Ok(expectedValue == actualValue, fmt.Sprintf("has expected environment variable %v", key))
		if actualValue != expectedValue {
			harness.Diagnosticf("environment variable %v expected: %v, actual: %v", key, expectedValue, actualValue)
		}
	}

	return nil
}

func validateLinuxProcess(harness *tap.T, spec *rspec.Spec) error {
	validateGeneralProcess(harness, spec)

	uid := os.Getuid()
	harness.Ok(uint32(uid) == spec.Process.User.UID, "has expected user ID")
	if uint32(uid) != spec.Process.User.UID {
		harness.Diagnosticf("user ID expected: %v, actual: %v", spec.Process.User.UID, uid)
	}

	gid := os.Getgid()
	harness.Ok(uint32(gid) == spec.Process.User.GID, "has expected group ID")
	if uint32(gid) != spec.Process.User.GID {
		harness.Diagnosticf("group ID expected: %v, actual: %v", spec.Process.User.GID, gid)
	}

	groups, err := os.Getgroups()
	if err != nil {
		return err
	}

	groupsMap := make(map[int]bool)
	for _, g := range groups {
		groupsMap[g] = true
	}

	for _, g := range spec.Process.User.AdditionalGids {
		harness.Ok(groupsMap[int(g)], fmt.Sprintf("has expected additional group ID %v", g))
	}

	cmdlineBytes, err := ioutil.ReadFile("/proc/1/cmdline")
	if err != nil {
		return err
	}

	args := bytes.Split(bytes.Trim(cmdlineBytes, "\x00"), []byte("\x00"))
	harness.Ok(len(args) == len(spec.Process.Args), "has expected number of process arguments")
	if len(args) != len(spec.Process.Args) {
		harness.Diagnosticf("expected process arguments: %v, actual: %v", spec.Process.Args, args)
	}
	for i, a := range args {
		harness.Ok(string(a) == spec.Process.Args[i], fmt.Sprintf("has expected process argument %d", i))
		if string(a) != spec.Process.Args[i] {
			harness.Diagnosticf("expected process argument %d: %v, actual: %v", i, spec.Process.Args[i], string(a))
		}
	}

	ret, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	noNewPrivileges := ret == 1
	harness.Ok(spec.Process.NoNewPrivileges == noNewPrivileges, "has expected noNewPrivileges")

	return nil
}

func validateCapabilities(harness *tap.T, spec *rspec.Spec) error {
	last := capability.CAP_LAST_CAP
	// workaround for RHEL6 which has no /proc/sys/kernel/cap_last_cap
	if last == capability.Cap(63) {
		last = capability.CAP_BLOCK_SUSPEND
	}

	processCaps, err := capability.NewPid(1)
	if err != nil {
		return err
	}

	expectedCaps := make(map[string]bool)
	for _, ec := range spec.Process.Capabilities {
		expectedCaps[ec] = true
	}

	for _, cap := range capability.List() {
		if cap > last {
			continue
		}

		capKey := fmt.Sprintf("CAP_%s", strings.ToUpper(cap.String()))
		expectedSet := expectedCaps[capKey]
		actuallySet := processCaps.Get(capability.EFFECTIVE, cap)
		if expectedSet {
			harness.Ok(actuallySet, fmt.Sprintf("expected capability %v set", capKey))
		} else {
			harness.Ok(!actuallySet, fmt.Sprintf("unexpected capability %v not set", capKey))
		}
	}

	return nil
}

func validateHostname(harness *tap.T, spec *rspec.Spec) error {
	if spec.Hostname == "" {
		harness.Skip(1, "hostname not set")
	} else {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		harness.Ok(hostname == spec.Hostname, "hostname matches expected value")
		if hostname != spec.Hostname {
			harness.Diagnosticf("hostname expected: %v, actual: %v", spec.Hostname, hostname)
		}
	}
	return nil
}

func validateRlimits(harness *tap.T, spec *rspec.Spec) error {
	for _, r := range spec.Process.Rlimits {
		rl, err := strToRlimit(r.Type)
		if err != nil {
			return err
		}

		var rlimit syscall.Rlimit
		if err := syscall.Getrlimit(rl, &rlimit); err != nil {
			return err
		}

		harness.Ok(rlimit.Cur == r.Soft, fmt.Sprintf("has expected soft %v", r.Type))
		if rlimit.Cur != r.Soft {
			harness.Diagnosticf("soft %v expected: %v, actual: %v", r.Type, r.Soft, rlimit.Cur)
		}
		harness.Ok(rlimit.Max == r.Hard, fmt.Sprintf("has expected hard %v", r.Type))
		if rlimit.Max != r.Hard {
			harness.Diagnosticf("hard %v expected: %v, actual: %v", r.Type, r.Hard, rlimit.Max)
		}
	}
	return nil
}

func validateSysctls(harness *tap.T, spec *rspec.Spec) error {
	for k, v := range spec.Linux.Sysctl {
		keyPath := filepath.Join("/proc/sys", strings.Replace(k, ".", "/", -1))
		vBytes, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return err
		}
		value := strings.TrimSpace(string(bytes.Trim(vBytes, "\x00")))
		harness.Ok(value == v, fmt.Sprintf("has expected sysctl %v", k))
		if value != v {
			harness.Diagnosticf("sysctl %v expected: %v, actual: %v", k, v, value)
		}
	}
	return nil
}

func testReadOnly(harness *tap.T, path string) error {
	tmpfile, err := ioutil.TempFile(path, "Test")
	harness.Ok(err != nil, fmt.Sprintf("%v is readonly (cannot create sub-file)", path))
	if err != nil {
		return err
	} else {
		tmpfile.Close()
		if err != nil {
			return err
		}

		err = os.RemoveAll(filepath.Join(path, tmpfile.Name()))
		if err != nil {
			return err
		}
	}

	return nil
}

func validateRootFS(harness *tap.T, spec *rspec.Spec) error {
	if spec.Root.Readonly {
		err := testReadOnly(harness, "/")
		if err != nil {
			return err
		}
	} else {
		harness.Skip(1, "root.readonly falsy")
	}

	return nil
}

func validateDefaultFS(harness *tap.T, spec *rspec.Spec) error {
	mountInfos, err := mount.GetMounts()
	if err != nil {
		return err
	}

	mountsMap := make(map[string]string)
	for _, mountInfo := range mountInfos {
		mountsMap[mountInfo.Mountpoint] = mountInfo.Fstype
	}

	for fs, fstype := range defaultFS {
		harness.Ok(mountsMap[fs] == fstype, fmt.Sprintf("mount %v has expected type", fs))
		if !(mountsMap[fs] == fstype) {
			harness.Diagnosticf("mount %v type expected: %v, actual: %v", fs, fstype, mountsMap[fs])
		}
	}

	return nil
}

func validateLinuxDevices(harness *tap.T, spec *rspec.Spec) error {
	if len(spec.Linux.Devices) == 0 {
		harness.Skip(1, "linux.devices (no devices configured)")
	}
	for _, device := range spec.Linux.Devices {
		fi, err := os.Stat(device.Path)
		if err != nil {
			return err
		}
		fStat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot determine state for device %s", device.Path)
		}
		var devType string
		switch fStat.Mode & syscall.S_IFMT {
		case syscall.S_IFCHR:
			devType = "c"
			break
		case syscall.S_IFBLK:
			devType = "b"
			break
		case syscall.S_IFIFO:
			devType = "p"
			break
		default:
			devType = "unmatched"
		}
		harness.Ok(devType == device.Type || (devType == "c" && device.Type == "u"), fmt.Sprintf("device %v has expected type", device.Path))
		if devType != device.Type && !(devType == "c" && device.Type == "u") {
			harness.Diagnosticf("device %v type expected: %v, actual: %v", device.Path, device.Type, devType)
		}
		if devType != "p" {
			dev := fStat.Rdev
			major := (dev >> 8) & 0xfff
			minor := (dev & 0xff) | ((dev >> 12) & 0xfff00)
			harness.Ok(int64(major) == device.Major, fmt.Sprintf("device %v has expected major number", device.Path))
			if int64(major) != device.Major {
				harness.Diagnosticf("device %v major number expected: %v, actual: %v", device.Path, device.Major, major)
			}
			harness.Ok(int64(minor) == device.Minor, fmt.Sprintf("device %v has expected minor number", device.Path))
			if int64(minor) != device.Minor {
				harness.Diagnosticf("device %v minor number expected: %v, actual: %v", device.Path, device.Minor, minor)
			}
		}
		if device.FileMode == nil {
			harness.Skip(1, fmt.Sprintf("device %v has unconfigured permissions", device.Path))
		} else {
			expectedPerm := *device.FileMode & os.ModePerm
			actualPerm := fi.Mode() & os.ModePerm
			harness.Ok(actualPerm == expectedPerm, fmt.Sprintf("device %v has expected permissions", device.Path))
			if actualPerm != expectedPerm {
				harness.Diagnosticf("device %v permissions expected: %v, actual: %v", device.Path, expectedPerm, actualPerm)
			}
		}
		if device.UID == nil {
			harness.Skip(1, fmt.Sprintf("device %v has an unconfigured user ID", device.Path))
		} else {
			harness.Ok(fStat.Uid == *device.UID, fmt.Sprintf("device %v has expected user ID", device.Path))
			if fStat.Uid != *device.UID {
				harness.Diagnosticf("device %v user ID epected: %v, actual: %v", device.Path, *device.UID, fStat.Uid)
			}
		}
		if device.GID == nil {
			harness.Skip(1, fmt.Sprintf("device %v has an unconfigured group ID", device.Path))
		} else {
			harness.Ok(fStat.Gid == *device.GID, fmt.Sprintf("device %v has expected group ID", device.Path))
			if fStat.Gid != *device.GID {
				harness.Diagnosticf("device %v group ID epected: %v, actual: %v", device.Path, *device.GID, fStat.Gid)
			}
		}
	}

	return nil
}

func validateDefaultSymlinks(harness *tap.T, spec *rspec.Spec) error {
	for symlink, dest := range defaultSymlinks {
		fi, err := os.Lstat(symlink)
		harness.Ok(err == nil, fmt.Sprintf("lstat default symlink %v", symlink))
		if err != nil {
			harness.Skip(1, fmt.Sprintf("default symlink %v checks (failed lstat)", symlink))
		} else {
			harness.Ok(fi.Mode()&os.ModeSymlink == os.ModeSymlink, fmt.Sprintf("default symlink %v is a symlink", symlink))
			realDest, err := os.Readlink(symlink)
			if err != nil {
				return err
			}
			harness.Ok(realDest == dest, fmt.Sprintf("default symlink %v has expected target", symlink))
			if realDest != dest {
				harness.Diagnosticf("default symlink %v target expected: %v, actual: %v", symlink, dest, realDest)
			}
		}
	}

	return nil
}

func validateDefaultDevices(harness *tap.T, spec *rspec.Spec) error {
	if spec.Process.Terminal {
		defaultDevices = append(defaultDevices, "/dev/console")
	}
	for _, device := range defaultDevices {
		fi, err := os.Stat(device)
		harness.Ok(err == nil, fmt.Sprintf("stat default device %v", device))
		if err != nil {
			harness.Skip(1, fmt.Sprintf("default device %v checks (failed stat)", device))
		} else {
			harness.Ok(fi.Mode()&os.ModeDevice == os.ModeDevice, fmt.Sprintf("default device %v is a device", device))
		}
	}

	return nil
}

func validateMaskedPaths(harness *tap.T, spec *rspec.Spec) error {
	for _, maskedPath := range spec.Linux.MaskedPaths {
		f, err := os.Open(maskedPath)
		harness.Ok(err == nil, fmt.Sprintf("open masked path %v", maskedPath))
		if err != nil {
			harness.Skip(1, fmt.Sprintf("masked path %v checks (failed open)", maskedPath))
		} else {
			defer f.Close()
			b := make([]byte, 1)
			_, err = f.Read(b)
			harness.Ok(err == io.EOF, fmt.Sprintf("masked path %v is not readable", maskedPath))
		}
	}
	return nil
}

func validateROPaths(harness *tap.T, spec *rspec.Spec) error {
	for _, v := range spec.Linux.ReadonlyPaths {
		err := testReadOnly(harness, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateOOMScoreAdj(harness *tap.T, spec *rspec.Spec) error {
	if spec.Linux.Resources == nil || spec.Linux.Resources.OOMScoreAdj == nil {
		harness.Skip(1, "linux.resources.oomScoreAdj falsy")
	} else {
		expected := *spec.Linux.Resources.OOMScoreAdj
		f, err := os.Open("/proc/1/oom_score_adj")
		harness.Ok(err == nil, "open /proc/1/oom_score_adj")
		if err != nil {
			harness.Skip(1, "oomScoreAdj checks (failed open)")
			return nil
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			err := s.Err()
			harness.Ok(err == nil, "scan /proc/1/oom_score_adj")
			if err != nil {
				harness.Skip(1, "oomScoreAdj checks (failed scan)")
				return nil
			}
			text := strings.TrimSpace(s.Text())
			actual, err := strconv.Atoi(text)
			harness.Ok(err == nil, "convert scanned /proc/1/oom_score_adj value to an integer")
			if err != nil {
				harness.Skip(1, "oomScoreAdj checks (failed integer conversion)")
				return nil
			}
			harness.Ok(actual == expected, "has expected oomScoreAdj")
			if actual != expected {
				harness.Diagnosticf("oomScoreAdj expected: %v, actual: %v", expected, actual)
			}
		}
	}

	return nil
}

func getIDMappings(path string) ([]rspec.IDMapping, error) {
	var idMaps []rspec.IDMapping
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		idMap := strings.Fields(strings.TrimSpace(s.Text()))
		if len(idMap) == 3 {
			hostID, err := strconv.ParseUint(idMap[0], 0, 32)
			if err != nil {
				return nil, err
			}
			containerID, err := strconv.ParseUint(idMap[1], 0, 32)
			if err != nil {
				return nil, err
			}
			mapSize, err := strconv.ParseUint(idMap[2], 0, 32)
			if err != nil {
				return nil, err
			}
			idMaps = append(idMaps, rspec.IDMapping{HostID: uint32(hostID), ContainerID: uint32(containerID), Size: uint32(mapSize)})
		} else {
			return nil, fmt.Errorf("invalid format in %v", path)
		}
	}

	return idMaps, nil
}

func validateIDMappings(harness *tap.T, mappings []rspec.IDMapping, path string, property string) error {
	if len(mappings) == 0 {
		harness.Skip(1, fmt.Sprintf("%s checks (no mappings specified)", property))
		return nil
	}
	idMaps, err := getIDMappings(path)
	harness.Ok(err == nil, fmt.Sprintf("get ID mappings from %s", path))
	if err != nil {
		harness.Skip(1, fmt.Sprintf("%s checks (failed to get mappings)", property))
		return nil
	}
	harness.Ok(len(idMaps) == len(mappings), fmt.Sprintf("%s has expected number of mappings", path))
	if len(idMaps) != len(mappings) {
		harness.Diagnosticf("expected %s mappings: %v, actual: %v", property, mappings, idMaps)
	}
	for _, v := range mappings {
		exist := false
		for _, cv := range idMaps {
			if v.HostID == cv.HostID && v.ContainerID == cv.ContainerID && v.Size == cv.Size {
				exist = true
				break
			}
		}
		harness.Ok(exist, fmt.Sprintf("%s has expected mapping %v", path, v))
		if !exist {
			harness.Diagnosticf("expected %s mappings: %v, actual: %v", property, mappings, idMaps)
		}
	}

	return nil
}

func validateUIDMappings(harness *tap.T, spec *rspec.Spec) error {
	return validateIDMappings(harness, spec.Linux.UIDMappings, "/proc/self/uid_map", "linux.uidMappings")
}

func validateGIDMappings(harness *tap.T, spec *rspec.Spec) error {
	return validateIDMappings(harness, spec.Linux.GIDMappings, "/proc/self/gid_map", "linux.gidMappings")
}

func mountMatch(specMount rspec.Mount, sysMount rspec.Mount) error {
	if filepath.Clean(specMount.Destination) != sysMount.Destination {
		return fmt.Errorf("mount destination expected: %v, actual: %v", specMount.Destination, sysMount.Destination)
	}

	if specMount.Type != sysMount.Type {
		return fmt.Errorf("mount %v type expected: %v, actual: %v", specMount.Destination, specMount.Type, sysMount.Type)
	}

	if filepath.Clean(specMount.Source) != sysMount.Source {
		return fmt.Errorf("mount %v source expected: %v, actual: %v", specMount.Destination, specMount.Source, sysMount.Source)
	}

	return nil
}

func validateMountsExist(harness *tap.T, spec *rspec.Spec) error {
	mountInfos, err := mount.GetMounts()
	if err != nil {
		return err
	}

	mountsMap := make(map[string][]rspec.Mount)
	for _, mountInfo := range mountInfos {
		m := rspec.Mount{
			Destination: mountInfo.Mountpoint,
			Type:        mountInfo.Fstype,
			Source:      mountInfo.Source,
		}
		mountsMap[mountInfo.Mountpoint] = append(mountsMap[mountInfo.Mountpoint], m)
	}

	for _, specMount := range spec.Mounts {
		found := false
		for _, sysMount := range mountsMap[filepath.Clean(specMount.Destination)] {
			if err := mountMatch(specMount, sysMount); err == nil {
				found = true
				harness.Pass(fmt.Sprintf("mount %q found", specMount.Destination))
				break
			}
		}
		if !found {
			harness.Fail(fmt.Sprintf("expected mount %q found", specMount.Destination))
		}
	}

	return nil
}

func validate(context *cli.Context) error {
	spec, err := loadSpecConfig()
	if err != nil {
		return err
	}

	defaultValidations := []validator{
		validateRootFS,
		validateHostname,
		validateMountsExist,
	}

	linuxValidations := []validator{
		validateCapabilities,
		validateDefaultSymlinks,
		validateDefaultFS,
		validateDefaultDevices,
		validateLinuxDevices,
		validateLinuxProcess,
		validateMaskedPaths,
		validateOOMScoreAdj,
		validateROPaths,
		validateRlimits,
		validateSysctls,
		validateUIDMappings,
		validateGIDMappings,
	}

	t := tap.New()
	t.Header(0)

	for _, v := range defaultValidations {
		err := v(t, spec)
		if err != nil {
			return err
		}
	}

	if spec.Platform.OS == "linux" {
		for _, v := range linuxValidations {
			err := v(t, spec)
			if err != nil {
				return err
			}
		}
	}
	t.AutoPlan()

	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "runtimetest"
	app.Version = "0.0.1"
	app.Usage = "Compare the environment with an OCI configuration"
	app.Description = "runtimetest compares its current environment with an OCI runtime configuration read from config.json in its current working directory.  The tests are fairly generic and cover most configurations used by the runtime validation suite, but there are corner cases where a container launched by a valid runtime would not satisfy runtimetest."
	app.UsageText = "runtimetest [options]"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "log-level",
			Value: "error",
			Usage: "Log level (panic, fatal, error, warn, info, or debug)",
		},
	}

	app.Action = validate
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
