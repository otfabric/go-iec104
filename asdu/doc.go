// SPDX-License-Identifier: MIT

// Package asdu implements the Application Service Data Unit of the
// IEC 60870-5 companion standards: the data unit identifier, the information
// objects and elements of IEC 60870-5-101 clause 7, and their binary codec.
//
// The package has no dependency on the IEC 60870-5-104 transport. The field
// widths that differ between companion standards (cause of transmission,
// common address and information object address size) are carried by
// [Params], so the same codec serves IEC 60870-5-104 ([IEC104]) and an
// IEC 60870-5-101 link layer.
//
// # Model
//
// An [ASDU] holds one type identification and a list of information objects
// of that type. Information objects are plain Go structs grouped by meaning
// rather than by type identification: a [SinglePoint] is encoded as
// M_SP_NA_1, M_SP_TA_1 or M_SP_TB_1 depending on [ASDU.Type]. [New] picks
// the type from the object: no time tag when Time is zero, CP56Time2a
// otherwise.
//
//	a := asdu.New(asdu.CauseSpontaneous, 1,
//		asdu.MeasuredFloat{IOA: 4001, Value: 49.98},
//		asdu.MeasuredFloat{IOA: 4002, Value: 231.4},
//	)
//	b, err := a.Encode(asdu.IEC104)
//
// Type identifications this package has no model for (the private range and
// reserved types) decode into [ASDU.Raw] and encode from it unchanged.
package asdu
