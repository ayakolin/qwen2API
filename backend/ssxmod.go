package main

import (
	"math"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 本文件移植自参考项目 Qwen2API_Go (internal/ssxmod/manager.go)。
//
// 阿里云 WAF 在浏览器端用一个 JS SDK (websdk-2.3.15d) 采集设备指纹、做 LZW
// 压缩后写入 ssxmod_itna / ssxmod_itna2 这两个 cookie。只要请求带上格式正确
// 的这两个 cookie，WAF 就会放行，不会返回人机验证挑战页。这里用 Go 复刻了
// 该 SDK 的指纹生成与 lz-string 风格的 6-bit LZW 编码（自定义 base64 字母表）。

const (
	ssxmodCustomBase64Chars = "DGi0YA7BemWnQjCl4_bR3f8SKIF9tUz/xhr2oEOgPpac=61ZqwTudLkM5vHyNXsVJ"
	ssxmodRefreshInterval   = 15 * time.Minute
)

// globalSsxmod 是包级共享的 cookie 生成器。ssxmod cookie 本质上是与具体账号
// 无关的 WAF 设备指纹，全局共享一份并按 TTL 刷新即可。
var globalSsxmod = newSsxmodManager()

// ssxmodManager 生成并缓存 ssxmod_itna/ssxmod_itna2 cookie，每 15 分钟刷新。
type ssxmodManager struct {
	mu        sync.RWMutex
	itna      string
	itna2     string
	timestamp int64
	rng       *rand.Rand
}

func newSsxmodManager() *ssxmodManager {
	m := &ssxmodManager{rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
	m.refreshLocked()
	return m
}

// Get 返回当前有效的 (ssxmod_itna, ssxmod_itna2)，过期则刷新。
func (m *ssxmodManager) Get() (string, string) {
	m.mu.RLock()
	valid := m.itna != "" && m.itna2 != "" && time.Since(time.UnixMilli(m.timestamp)) < ssxmodRefreshInterval
	if valid {
		itna, itna2 := m.itna, m.itna2
		m.mu.RUnlock()
		return itna, itna2
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.itna == "" || m.itna2 == "" || time.Since(time.UnixMilli(m.timestamp)) >= ssxmodRefreshInterval {
		m.refreshLocked()
	}
	return m.itna, m.itna2
}

func (m *ssxmodManager) refreshLocked() {
	fields := m.generateFingerprintFields()
	processed := m.processFields(fields)

	m.itna = "1-" + ssxmodCustomEncode(strings.Join(processed, "^"))
	m.itna2 = "1-" + ssxmodCustomEncode(strings.Join([]string{
		processed[0],
		processed[1],
		processed[23],
		"0", "", "0", "", "", "0",
		"0", "0",
		processed[32],
		processed[33],
		"0", "0", "0", "0", "0",
	}, "^"))
	m.timestamp = time.Now().UnixMilli()
}

func (m *ssxmodManager) generateFingerprintFields() []string {
	return []string{
		m.generateDeviceID(),
		"websdk-2.3.15d",
		"1765348410850",
		"91",
		"1|15",
		"zh-CN",
		"-480",
		"16705151|12791",
		"1470|956|283|797|158|0|1470|956|1470|798|0|0",
		"5",
		"MacIntel",
		"10",
		"ANGLE (Apple, ANGLE Metal Renderer: Apple M4, Unspecified Version)|Google Inc. (Apple)",
		"30|30",
		"0",
		"28",
		"5|" + strconv.FormatUint(uint64(m.randomHash()), 10),
		strconv.FormatUint(uint64(m.randomHash()), 10),
		strconv.FormatUint(uint64(m.randomHash()), 10),
		"1",
		"0",
		"1",
		"0",
		"P",
		"0",
		"0",
		"0",
		"416",
		"Google Inc.",
		"8",
		"-1|0|0|0|0",
		strconv.FormatUint(uint64(m.randomHash()), 10),
		"11",
		strconv.FormatInt(time.Now().UnixMilli(), 10),
		strconv.FormatUint(uint64(m.randomHash()), 10),
		"0",
		strconv.Itoa(m.rng.Intn(91) + 10),
	}
}

func (m *ssxmodManager) processFields(fields []string) []string {
	processed := append([]string(nil), fields...)
	m.replaceSplitHash(processed, 16)
	m.replaceFullHash(processed, 17)
	m.replaceFullHash(processed, 18)
	m.replaceFullHash(processed, 31)
	m.replaceFullHash(processed, 34)
	processed[36] = strconv.Itoa(m.rng.Intn(91) + 10)
	processed[33] = strconv.FormatInt(time.Now().UnixMilli(), 10)
	return processed
}

func (m *ssxmodManager) replaceSplitHash(fields []string, idx int) {
	parts := strings.Split(fields[idx], "|")
	if len(parts) == 2 {
		fields[idx] = parts[0] + "|" + strconv.FormatUint(uint64(m.randomHash()), 10)
	}
}

func (m *ssxmodManager) replaceFullHash(fields []string, idx int) {
	fields[idx] = strconv.FormatUint(uint64(m.randomHash()), 10)
}

func (m *ssxmodManager) generateDeviceID() string {
	const chars = "0123456789abcdef"
	var b strings.Builder
	b.Grow(20)
	for i := 0; i < 20; i++ {
		b.WriteByte(chars[m.rng.Intn(len(chars))])
	}
	return b.String()
}

func (m *ssxmodManager) randomHash() uint32 {
	return m.rng.Uint32()
}

func ssxmodCustomEncode(data string) string {
	// urlSafe 模式（cookie 用），不补 '=' padding。
	return ssxmodLZWCompress(data, 6, func(index int) byte {
		return ssxmodCustomBase64Chars[index]
	})
}

// ssxmodLZWCompress 复刻 lz-string 风格的 6-bit LZW 压缩，输出用自定义 base64
// 字母表编码。算法与参考项目逐位对齐。
func ssxmodLZWCompress(data string, bits int, charFunc func(index int) byte) string {
	if data == "" {
		return ""
	}

	dict := map[string]int{}
	dictToCreate := map[string]bool{}
	w := ""
	enlargeIn := 2
	dictSize := 3
	numBits := 2
	result := make([]byte, 0, len(data))
	value := 0
	position := 0

	writeBit := func(bit int) {
		value = (value << 1) | bit
		if position == bits-1 {
			position = 0
			result = append(result, charFunc(value))
			value = 0
		} else {
			position++
		}
	}

	writeCharBits := func(charCode int, count int) {
		for i := 0; i < count; i++ {
			writeBit(charCode & 1)
			charCode >>= 1
		}
	}

	flushCreated := func(token string) {
		if token == "" {
			return
		}
		runes := []rune(token)
		first := int(runes[0])
		if first < 256 {
			for i := 0; i < numBits; i++ {
				writeBit(0)
			}
			writeCharBits(first, 8)
		} else {
			writeBit(1)
			for i := 1; i < numBits; i++ {
				writeBit(0)
			}
			writeCharBits(first, 16)
		}
		enlargeIn--
		if enlargeIn == 0 {
			enlargeIn = int(math.Pow(2, float64(numBits)))
			numBits++
		}
		delete(dictToCreate, token)
	}

	flushCode := func(code int) {
		writeCharBits(code, numBits)
		enlargeIn--
		if enlargeIn == 0 {
			enlargeIn = int(math.Pow(2, float64(numBits)))
			numBits++
		}
	}

	for _, r := range data {
		c := string(r)
		if _, ok := dict[c]; !ok {
			dict[c] = dictSize
			dictSize++
			dictToCreate[c] = true
		}

		wc := w + c
		if _, ok := dict[wc]; ok {
			w = wc
			continue
		}

		if dictToCreate[w] {
			flushCreated(w)
		} else {
			flushCode(dict[w])
		}

		dict[wc] = dictSize
		dictSize++
		w = c
	}

	if w != "" {
		if dictToCreate[w] {
			flushCreated(w)
		} else {
			flushCode(dict[w])
		}
	}

	writeCharBits(2, numBits)
	for {
		value <<= 1
		if position == bits-1 {
			result = append(result, charFunc(value))
			break
		}
		position++
	}

	return string(result)
}
