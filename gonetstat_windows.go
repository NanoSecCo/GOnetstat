package GOnetstat

import(
	"fmt"
	"os/exec"
"github.com/justvisiting/hawthrone/gonanoshared"
)

func Tcp() []gonanoshared.Process {
	// Get a slice of Process type with TCP data
	//data := netstat("tcp")
	out, err := exec.Command("cmd", "/C", "netstat", "-ao", "-p", "tcp").Output()

	if err != nil {
		fmt.Println("Error: ", err)
	} else {
		res := string(out)
		fmt.Println(res)
	}


	return nil
}
