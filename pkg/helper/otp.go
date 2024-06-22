package smtp

import "math/rand"

func GenerateOTP() int {

	return rand.Intn(900000) + 100000
}
	