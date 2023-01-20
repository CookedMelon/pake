package aes

type AES_KEY struct {
	roundKey [176]byte
}
func SubBytes(state [16]byte) {
	for i := 0; i < 16; i++ {
		state[i] = stb[state[i]]
	}
}
func ShiftRows(state [16]byte) {
	state[4], state[5], state[6], state[7] = state[5], state[6], state[7], state[4]
	state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
	state[12], state[13], state[14], state[15] = state[15], state[12], state[13], state[14]
}
func MixColumns(state [16]byte) {
	for i := 0; i < 4; i++ {
		s0 := state[i]
		s1 := state[i+4]
		s2 := state[i+8]
		s3 := state[i+12]
		state[i] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3
		state[i+4] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3
		state[i+8] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3)
		state[i+12] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3)
	}
}
func gmul2(a byte) byte {
	if a&0x80 != 0 {
		return ((a << 1) & ((1 << 8) - 1)) ^ 0x1b
	}
	return a << 2
}
func gmul3(a byte) byte {
	return gmul2(a) ^ a
}
func AES_init_ctx(ctx *AES_KEY, key []byte) {
	KeyExpansion(ctx.roundKey, key)
}
func KeyExpansion(keyEx [176]byte, key []byte) {
	for i := 0; i < 16; i++ {
		keyEx[i*4] = key[i*4]
		keyEx[i*4+1] = key[i*4+1]
		keyEx[i*4+2] = key[i*4+2]
		keyEx[i*4+3] = key[i*4+3]
	}
	temp := [4]byte{}
	for i := 16;i<44; i++ {
		k := (i - 1)*4
		temp[0] = keyEx[k]
		temp[1] = keyEx[k+1]
		temp[2] = keyEx[k+2]
		temp[3] = keyEx[k+3]

		if i%16 == 0 {
			t:=temp[0]
			temp[0] = stb[temp[1]]
			temp[1] = stb[temp[2]]
			temp[2] = stb[temp[3]]
			temp[3] = stb[t]
			temp[0] ^= RC[i/16]
		}
		j := i * 4;k = (i - 4) * 4
		keyEx[j] = keyEx[k]^temp[0]
		keyEx[j+1] = keyEx[k+1]^temp[1]
		keyEx[j+2] = keyEx[k+2]^temp[2]
		keyEx[j+3] = keyEx[k+3]^temp[3]
	}
}
func XorWithIv(buf []byte, iv []byte) {
	for i := 0; i < 16; i++ {
		buf[i] ^= iv[i]
	}
}
func AddRoundKey(round int, state [16]byte, keyEx [176]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i*4+j] ^= keyEx[round*16+i*4+j]
		}
	}
}
func Cipher(state [16]byte, keyEx [176]byte) {
	AddRoundKey(0, state, keyEx)
	for i := 1; ; i++ {
		SubBytes(state)
		ShiftRows(state)
		if i == 10 {
			break
		}
		MixColumns(state)
		AddRoundKey(i, state, keyEx)
	}
	AddRoundKey(10,state, keyEx)
}
func AES_CBC_encrypt_buffer(ctx *AES_KEY, buf [16]byte,length int) {
	iv:=make([]byte,16)
	for i := 0; i < length; i += 16 {
		XorWithIv(buf[i:], iv[:])
		Cipher(buf, ctx.roundKey)
		iv = buf[i:]
	}
}
