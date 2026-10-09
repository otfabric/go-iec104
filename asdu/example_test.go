// SPDX-License-Identifier: MIT

package asdu_test

import (
	"fmt"
	"time"

	"github.com/otfabric/go-iec104/asdu"
)

func ExampleNew() {
	at := time.Date(2026, 10, 9, 15, 35, 12, 345e6, time.UTC)

	// Without a time tag the plain type is chosen, with one the CP56Time2a type.
	plain := asdu.New(asdu.CauseInterrogatedStation, 1, asdu.MeasuredFloat{IOA: 4001, Value: 49.98})
	tagged := asdu.New(asdu.CauseSpontaneous, 1, asdu.MeasuredFloat{IOA: 4001, Value: 49.98, Time: asdu.At(at)})

	fmt.Println(plain)
	fmt.Println(tagged)
	// Output:
	// M_ME_NC_1 interrogated-station ca=1 n=1
	// M_ME_TF_1 spontaneous ca=1 n=1
}

func ExampleASDU_Encode() {
	a := asdu.New(asdu.CauseActivation, 1, asdu.Interrogation{Qualifier: asdu.QOIStation})
	wire, err := a.Encode(asdu.IEC104)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("% X\n", wire)
	// Output:
	// 64 01 06 00 01 00 00 00 00 14
}

func ExampleDecode() {
	wire := []byte{0x01, 0x82, 0x14, 0x00, 0x01, 0x00, 0xE8, 0x03, 0x00, 0x01, 0x80}
	a, err := asdu.Decode(wire, asdu.IEC104)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(a)
	for _, obj := range a.Objects {
		switch o := obj.(type) {
		case asdu.SinglePoint:
			fmt.Printf("ioa=%d value=%v quality=%s\n", o.IOA, o.Value, o.Quality)
		}
	}
	// Output:
	// M_SP_NA_1 interrogated-station ca=1 n=2 sq
	// ioa=1000 value=true quality=good
	// ioa=1001 value=false quality=IV
}

func ExampleASDU_Reply() {
	req := asdu.New(asdu.CauseActivation, 1, asdu.SingleCommand{IOA: 6001, Value: true})
	fmt.Println(req.Reply(asdu.CauseActivationCon, false))
	fmt.Println(req.Reply(asdu.CauseUnknownIOA, true))
	// Output:
	// C_SC_NA_1 activation-con ca=1 n=1
	// C_SC_NA_1 unknown-ioa ca=1 n=1 negative
}
