package captcha

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────
// Regexes
// ─────────────────────────────────────────────

var (
	moduleStartRe = regexp.MustCompile(
		`(?s)const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*Object\.freeze\(\s*` +
			`(?:Object\.defineProperty\(\s*)?\{`,
	)
	encryptFieldRe = regexp.MustCompile(`encryptText\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)`)
	decryptFieldRe = regexp.MustCompile(`decryptText\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)`)

	funcDeclRe  = regexp.MustCompile(`(?s)(?:^|[;\n}])\s*function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{`)
	constDeclRe = regexp.MustCompile(`(?m)(?:^|[;\n}])\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=`)
	jsIdentRe   = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

	// general shift patterns — যেকোনো variable name handle করে
	plusShiftRe  = regexp.MustCompile(`\+\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\[`)
	minusShiftRe = regexp.MustCompile(`-\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\[`)
)

var jsKeywords = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true,
	"const": true, "continue": true, "debugger": true, "default": true,
	"delete": true, "do": true, "else": true, "export": true,
	"extends": true, "finally": true, "for": true, "function": true,
	"if": true, "import": true, "in": true, "instanceof": true,
	"let": true, "new": true, "return": true, "super": true,
	"switch": true, "this": true, "throw": true, "try": true,
	"typeof": true, "var": true, "void": true, "while": true,
	"with": true, "yield": true, "null": true, "true": true, "false": true,
	"async": true, "await": true, "of": true, "static": true, "get": true,
	"set": true, "undefined": true, "NaN": true, "Infinity": true,
}

// ─────────────────────────────────────────────
// Version fingerprints — seed-based detection
// ─────────────────────────────────────────────

// VersionSeeds — version-specific algorithm signatures (JS সংখ্যা)।
// এই সংখ্যাগুলো JS-এ থাকলে সেই version-এর keystream function।
// Function name, module order, obfuscation — সব independent।
var VersionSeeds = map[int][]string{
	2:  {"1103515245", "12345"},
	5:  {"74565", "424090", "773615"},        // Fibonacci 3-LFSR
	6:  {"67"},                               // polynomial rolling hash
	8:  {"1103515245", "12345", "123456789"}, // LCG imul+add
	9:  {"3.99"},                             // logistic map
	10: {"1000036000099", "314159265"},       // modular exponent
}

// ─────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────

// ExtractJSSnippetVersioned — version-aware JS extractor।
//
// Primary: seed-based (version-specific fingerprint দিয়ে keystream function
// খুঁজে, তার caller = encrypt/decrypt)। Function name, module order — independent।
//
// Fallback: module-order-based (seed map-এ version না থাকলে)।
func ExtractJSSnippetVersioned(src string, version int) (string, error) {
	fmt.Fprintf(os.Stderr, "[captcha-extract] version=%d\n", version)

	// ১. seed-based (নির্ভরযোগ্য)
	if seeds, ok := VersionSeeds[version]; ok && len(seeds) > 0 {
		fmt.Fprintf(os.Stderr, "[captcha-extract] trying seed-based (seeds=%v)\n", seeds)
		snippet, err := extractBySeed(src, version, seeds)
		if err == nil {
			fmt.Fprintf(os.Stderr, "[captcha-extract] → seed-based OK\n")
			return snippet, nil
		}
		fmt.Fprintf(os.Stderr, "[captcha-extract] seed-based failed: %v → fallback module-order\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[captcha-extract] no seed fingerprint for v%d → module-order\n", version)
	}

	// ২. module-order fallback
	return extractByModuleIndex(src, version)
}

// ExtractJSSnippet — legacy (module-order, first module)
func ExtractJSSnippet(src string) (string, error) {
	return extractByModuleIndex(src, 1)
}

// ─────────────────────────────────────────────
// Seed-based extraction
// ─────────────────────────────────────────────

func extractBySeed(src string, version int, seeds []string) (string, error) {
	funcs := collectFunctions(src)
	if len(funcs) == 0 {
		return "", fmt.Errorf("no functions found")
	}
	fmt.Fprintf(os.Stderr, "[captcha-extract]   scanning %d functions for seeds\n", len(funcs))

	// keystream = যেই function-এ সব seed string আছে
	keystreamName := ""
	for i := range funcs {
		body := src[funcs[i].bodyStart:funcs[i].bodyEnd]
		if containsAll(body, seeds) {
			keystreamName = funcs[i].name
			break
		}
	}
	if keystreamName == "" {
		return "", fmt.Errorf("keystream with seeds %v not found", seeds)
	}
	fmt.Fprintf(os.Stderr, "[captcha-extract]   keystream=%s\n", keystreamName)

	// encrypt/decrypt = keystream-কে call করে + shift করে
	encryptName := ""
	decryptName := ""
	for i := range funcs {
		fn := &funcs[i]
		if fn.name == keystreamName {
			continue
		}
		body := src[fn.bodyStart:fn.bodyEnd]
		if !strings.Contains(body, keystreamName) {
			continue
		}
		hasPlus := plusShiftRe.MatchString(body)
		hasMinus := minusShiftRe.MatchString(body)
		fmt.Fprintf(os.Stderr, "[captcha-extract]   candidate %s calls %s (plus=%v minus=%v)\n",
			fn.name, keystreamName, hasPlus, hasMinus)
		if hasPlus && encryptName == "" {
			encryptName = fn.name
		}
		if hasMinus && decryptName == "" {
			decryptName = fn.name
		}
	}

	// fallback — keystream-কে call করা function-এর মধ্যে প্রথমটা encrypt, দ্বিতীয়টা decrypt
	if encryptName == "" || decryptName == "" {
		var callers []string
		for i := range funcs {
			fn := &funcs[i]
			if fn.name == keystreamName {
				continue
			}
			body := src[fn.bodyStart:fn.bodyEnd]
			if strings.Contains(body, keystreamName) {
				callers = append(callers, fn.name)
			}
		}
		fmt.Fprintf(os.Stderr, "[captcha-extract]   callers of %s: %v\n", keystreamName, callers)
		if len(callers) >= 2 {
			if encryptName == "" {
				encryptName = callers[0]
			}
			if decryptName == "" {
				decryptName = callers[1]
			}
		} else if len(callers) == 1 && encryptName == "" {
			encryptName = callers[0]
		}
	}

	if encryptName == "" || decryptName == "" {
		return "", fmt.Errorf("enc/dec not found (ks=%s enc=%s dec=%s)",
			keystreamName, encryptName, decryptName)
	}
	fmt.Fprintf(os.Stderr, "[captcha-extract]   enc=%s dec=%s\n", encryptName, decryptName)

	deps, err := collectDependencies(src, keystreamName, encryptName, decryptName)
	if err != nil {
		return "", err
	}
	alphabet := findAlphabetString(src, deps)

	var b strings.Builder
	fmt.Fprintf(&b, "// auto-extracted captcha v%d (seed-based: ks=%s enc=%s dec=%s)\n",
		version, keystreamName, encryptName, decryptName)
	b.WriteString(deps)
	b.WriteString("\n")
	b.WriteString("globalThis.__captcha = {\n")
	fmt.Fprintf(&b, "  encrypt: %s,\n", encryptName)
	fmt.Fprintf(&b, "  decrypt: %s,\n", decryptName)
	fmt.Fprintf(&b, "  keystream: %s,\n", keystreamName)
	if alphabet != "" {
		fmt.Fprintf(&b, "  alphabet: %q,\n", alphabet)
	}
	b.WriteString("};\n")
	return b.String(), nil
}

// ─────────────────────────────────────────────
// Module-order fallback
// ─────────────────────────────────────────────

type moduleMatch struct {
	name        string
	encryptName string
	decryptName string
	start       int
}

func findAllModules(src string) []moduleMatch {
	var out []moduleMatch
	matches := moduleStartRe.FindAllStringSubmatchIndex(src, -1)
	for _, m := range matches {
		mod := moduleMatch{
			name:  src[m[2]:m[3]],
			start: m[0],
		}
		openBrace := strings.LastIndex(src[m[0]:m[1]], "{")
		if openBrace < 0 {
			continue
		}
		openBrace += m[0]
		closeBrace := matchBrace(src, openBrace)
		if closeBrace < 0 {
			continue
		}
		block := src[openBrace : closeBrace+1]

		if em := encryptFieldRe.FindStringSubmatch(block); em != nil {
			mod.encryptName = em[1]
		}
		if dm := decryptFieldRe.FindStringSubmatch(block); dm != nil {
			mod.decryptName = dm[1]
		}
		if mod.encryptName != "" && mod.decryptName != "" {
			out = append(out, mod)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

func extractByModuleIndex(src string, version int) (string, error) {
	modules := findAllModules(src)
	fmt.Fprintf(os.Stderr, "[captcha-extract] module-order: found %d modules\n", len(modules))
	for i, m := range modules {
		fmt.Fprintf(os.Stderr, "[captcha-extract]   [%d] %s enc=%s dec=%s\n",
			i, m.name, m.encryptName, m.decryptName)
	}
	if len(modules) == 0 {
		return "", fmt.Errorf("no modules found")
	}
	if version < 1 || version > len(modules) {
		return "", fmt.Errorf("version %d out of range (1..%d)", version, len(modules))
	}

	chosen := &modules[version-1]
	fmt.Fprintf(os.Stderr, "[captcha-extract] CHOSEN [%d] %s enc=%s dec=%s\n",
		version-1, chosen.name, chosen.encryptName, chosen.decryptName)

	deps, err := collectDependencies(src, chosen.encryptName, chosen.decryptName)
	if err != nil {
		return "", err
	}
	alphabet := findAlphabetString(src, deps)

	var b strings.Builder
	fmt.Fprintf(&b, "// auto-extracted captcha v%d (module=%s enc=%s dec=%s)\n",
		version, chosen.name, chosen.encryptName, chosen.decryptName)
	b.WriteString(deps)
	b.WriteString("\n")
	b.WriteString("globalThis.__captcha = {\n")
	fmt.Fprintf(&b, "  encrypt: %s,\n", chosen.encryptName)
	fmt.Fprintf(&b, "  decrypt: %s,\n", chosen.decryptName)
	if alphabet != "" {
		fmt.Fprintf(&b, "  alphabet: %q,\n", alphabet)
	}
	b.WriteString("};\n")
	return b.String(), nil
}

// ─────────────────────────────────────────────
// Function collection
// ─────────────────────────────────────────────

type jsFunc struct {
	name      string
	start     int
	end       int
	bodyStart int
	bodyEnd   int
}

func collectFunctions(src string) []jsFunc {
	var out []jsFunc
	seen := make(map[string]bool)
	for _, m := range funcDeclRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		if seen[name] {
			continue
		}
		bodyStart := m[1]
		bodyEnd := matchBrace(src, bodyStart-1)
		if bodyEnd < 0 {
			continue
		}
		stmtStart := strings.Index(src[m[0]:m[1]], "function")
		if stmtStart < 0 {
			continue
		}
		stmtStart += m[0]
		out = append(out, jsFunc{
			name:      name,
			start:     stmtStart,
			end:       bodyEnd + 1,
			bodyStart: bodyStart,
			bodyEnd:   bodyEnd,
		})
		seen[name] = true
	}
	return out
}

// ─────────────────────────────────────────────
// Dependency collection
// ─────────────────────────────────────────────

type jsDecl struct {
	name  string
	body  string
	start int
}

func collectDependencies(src string, rootNames ...string) (string, error) {
	decls := collectTopLevelDecls(src)
	if len(decls) == 0 {
		return "", fmt.Errorf("no top-level declarations")
	}
	declByName := make(map[string]jsDecl, len(decls))
	for _, d := range decls {
		if _, exists := declByName[d.name]; !exists {
			declByName[d.name] = d
		}
	}
	for _, r := range rootNames {
		if _, ok := declByName[r]; !ok {
			return "", fmt.Errorf("root %q not found", r)
		}
	}

	needed := make(map[string]bool)
	queue := append([]string{}, rootNames...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if needed[name] {
			continue
		}
		d, ok := declByName[name]
		if !ok {
			continue
		}
		needed[name] = true
		for _, ref := range extractIdentifiers(d.body) {
			if needed[ref] {
				continue
			}
			if _, ok := declByName[ref]; ok {
				queue = append(queue, ref)
			}
		}
	}

	sortDeclsByPos(decls)

	var b strings.Builder
	emitted := make(map[string]bool)
	for _, d := range decls {
		if needed[d.name] && !emitted[d.name] {
			body := strings.TrimRight(d.body, " \t\r\n")
			b.WriteString(body)
			if !strings.HasSuffix(body, ";") && !strings.HasSuffix(body, "}") {
				b.WriteString(";")
			}
			b.WriteString("\n")
			emitted[d.name] = true
		}
	}
	return b.String(), nil
}

func collectTopLevelDecls(src string) []jsDecl {
	var out []jsDecl
	seen := make(map[string]bool)

	for _, m := range funcDeclRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		if seen[name] {
			continue
		}
		bodyStart := m[1]
		bodyEnd := matchBrace(src, bodyStart-1)
		if bodyEnd < 0 {
			continue
		}
		stmtStart := strings.Index(src[m[0]:m[1]], "function")
		if stmtStart < 0 {
			continue
		}
		stmtStart += m[0]
		out = append(out, jsDecl{name: name, body: src[stmtStart : bodyEnd+1], start: stmtStart})
		seen[name] = true
	}

	for _, m := range constDeclRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		if seen[name] {
			continue
		}
		kwStart := -1
		for _, kw := range []string{"const", "let", "var"} {
			idx := strings.Index(src[m[0]:m[1]], kw)
			if idx >= 0 {
				kwStart = m[0] + idx
				break
			}
		}
		if kwStart < 0 {
			continue
		}
		end := findStatementEnd(src, m[1])
		if end <= kwStart {
			continue
		}
		out = append(out, jsDecl{name: name, body: src[kwStart:end], start: kwStart})
		seen[name] = true
	}
	return out
}

func findStatementEnd(src string, from int) int {
	depth := 0
	inString := byte(0)
	for i := from; i < len(src); i++ {
		ch := src[i]
		if inString != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		switch ch {
		case '"', '\'', '`':
			inString = ch
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				return i + 1
			}
		case '\n':
			if depth == 0 {
				return i
			}
		}
	}
	return len(src)
}

func matchBrace(src string, openPos int) int {
	if openPos < 0 || openPos >= len(src) || src[openPos] != '{' {
		return -1
	}
	depth := 0
	inString := byte(0)
	for i := openPos; i < len(src); i++ {
		ch := src[i]
		if inString != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		switch ch {
		case '"', '\'', '`':
			inString = ch
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func extractIdentifiers(src string) []string {
	clean := stripStringsAndComments(src)
	seen := make(map[string]bool)
	var out []string
	for _, id := range jsIdentRe.FindAllString(clean, -1) {
		if jsKeywords[id] {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func stripStringsAndComments(src string) string {
	out := []byte(src)
	i := 0
	for i < len(out) {
		ch := out[i]
		if ch == '/' && i+1 < len(out) && out[i+1] == '/' {
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
			continue
		}
		if ch == '/' && i+1 < len(out) && out[i+1] == '*' {
			out[i] = ' '
			out[i+1] = ' '
			i += 2
			for i+1 < len(out) && !(out[i] == '*' && out[i+1] == '/') {
				out[i] = ' '
				i++
			}
			if i+1 < len(out) {
				out[i] = ' '
				out[i+1] = ' '
				i += 2
			}
			continue
		}
		if ch == '"' || ch == '\'' || ch == '`' {
			quote := ch
			out[i] = ' '
			i++
			for i < len(out) {
				if out[i] == '\\' {
					out[i] = ' '
					i++
					if i < len(out) {
						out[i] = ' '
						i++
					}
					continue
				}
				if out[i] == quote {
					out[i] = ' '
					i++
					break
				}
				out[i] = ' '
				i++
			}
			continue
		}
		i++
	}
	return string(out)
}

func findAlphabetString(src, deps string) string {
	re := regexp.MustCompile(`"([A-Za-z0-9_\-]{64})"`)
	for _, m := range re.FindAllStringSubmatch(deps, -1) {
		if hasAllClasses(m[1]) {
			return m[1]
		}
	}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		if hasAllClasses(m[1]) {
			return m[1]
		}
	}
	return ""
}

func hasAllClasses(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, ch := range s {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func containsAll(haystack string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}

func sortDeclsByPos(decls []jsDecl) {
	for i := 1; i < len(decls); i++ {
		for j := i; j > 0 && decls[j].start < decls[j-1].start; j-- {
			decls[j], decls[j-1] = decls[j-1], decls[j]
		}
	}
}
