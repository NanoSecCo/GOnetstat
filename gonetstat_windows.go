// Functionality inspired from mig.ninja/mig/modules/netstat package

package GOnetstat

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"os/exec"
	"fmt"
	"github.com/nanosecco/hawthrone/gonanoshared"
	"github.com/nanosecco/go-ps"
)

var errSkip = errors.New("skip")


func Tcp() ([]gonanoshared.Process) {   

    return getNetStatData("tcp")
}

func Tcp6() ([]gonanoshared.Process) {

    return getNetStatData("tcpv6")
}

func getNetStatData(proto string) ([]gonanoshared.Process){

	processes := []gonanoshared.Process{}

	out, err := exec.Command("cmd", "/C", "netstat", "-aon", "-p", proto).Output()
    if err!=nil{
		fmt.Println("Netstat command failed - ", err)
		return nil
    }

	n := NetstatWinOutput{}

	if err = n.UnmarshalText(out); err!=nil{
		return nil
	}

	for _, v := range n.Entries{

		pidInt, err := strconv.Atoi(v.PID)
		p, err := ps.FindProcess(pidInt)
		if err!=nil{
			fmt.Println("Cannot find process - ", pidInt, err)
			return nil
		}

		var processExecutable, processName = "Unknown", "Unknown"

		if p != nil{
			processExecutable = p.Executable()
			processName = getProcessNameFromExecutable(processExecutable)
		}

		processes = 
		append(processes, gonanoshared.Process{
				Pid: v.PID, 
				Exe: processExecutable,
				Name: processName,
				State: v.State, 
				Ip: v.LocalIP.String(), 
				Port: v.LocalPort,
				ForeignIp: v.RemoteIP.String(), 
				ForeignPort: v.RemotePort,
			},
		)
	}

	return processes
}

// NetstatWinOutput supports functions for parsing and responding to queries based on the output of the windows netstat -nao command.
type NetstatWinOutput struct {
	Entries []netstatWinEntry
}


// UnmarshalText parses the output of windows netstat -nao containing IPv4 and IPv6 addresses into the NetstatWinOutput struct.
//  Sample windows netstat -nao output:
//   Active Connections
//   Proto  Local Address          Foreign Address        State			PID
//   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING		460
//   TCP    0.0.0.0:445            0.0.0.0:0              LISTENING		4
func (n *NetstatWinOutput) UnmarshalText(text []byte) error {
	n.Entries = []netstatWinEntry{}
	buf := bytes.NewReader(text)
	reader := bufio.NewReader(buf)
	for {
		lineBytes, _, err := reader.ReadLine()
		if err != nil {
			break
		}
		entry := netstatWinEntry{}
		err = entry.UnmarshalText(lineBytes)
		if err != nil {
			if err != errSkip {
				fmt.Println("Cannot unmarshal netstat data - ", err)
				return err
			}
			continue
		}
		n.Entries = append(n.Entries, entry)
	}
	return nil
}

type netstatWinEntry struct {
	Proto       string
	LocalIP     net.IP
	LocalPort   int64
	RemoteIP    net.IP
	RemotePort  int64
	RemoteValue string
	State       string
	PID 		string
}

func (n *netstatWinEntry) UnmarshalText(text []byte) (err error) {
	fields := strings.Fields(string(text))
	if len(fields) < 5 {
		return errSkip
	}

	if len(fields) == 5 {
		n.State = string(fields[3])
		n.PID = string(fields[4])
	}

	n.Proto = fields[0]

	if n.Proto == "Proto" { // Heading line
		return errSkip
	}

	if n.LocalIP, n.LocalPort, err = n.parseEndpointString(fields[1]); err != nil {
		return errSkip
	}

	// don't return err if local is ok
	var xerr error
	if n.RemoteIP, n.RemotePort, xerr = n.parseEndpointString(fields[2]); xerr != nil {
		n.RemoteValue = fields[2]
	}
	return
}

var endpoint_win_re = regexp.MustCompile("^(.*?)(%[a-z0-9]+)?:(\\*|[0-9]+)$")

func (n *netstatWinEntry) parseEndpointString(str string) (ip net.IP, port int64, err error) {
	port = -1
	matches := endpoint_win_re.FindStringSubmatch(str)
	if matches != nil {
		if matches[1] == "*" {
			return
		}
		ip = net.ParseIP(matches[1])
		if matches[3] != "*" {
			if p, err := strconv.Atoi(matches[3]); err == nil {
				port = int64(p)
			}
		}
	}
	return
}


func getProcessNameFromExecutable(exe string) (pName string){

	pName = exe

	if strings.HasSuffix(exe, ".exe"){
		pName = strings.TrimSuffix(exe, ".exe")
	}

	return
}

