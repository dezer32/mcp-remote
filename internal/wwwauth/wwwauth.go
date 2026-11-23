// Package wwwauth разбирает заголовок WWW-Authenticate (схема Bearer,
// RFC 6750 §3). Им пользуются httpmcp (диагностика 401) и oauth (discovery по
// resource_metadata).
package wwwauth

import "strings"

// ParseBearer разбирает значение заголовка WWW-Authenticate для схемы Bearer
// (RFC 6750 §3) и возвращает параметры в виде map с ключами в нижнем регистре.
// Возвращает nil, если challenge не Bearer.
func ParseBearer(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Префикс схемы (case-insensitive).
	const scheme = "bearer"
	if len(s) < len(scheme) || !strings.EqualFold(s[:len(scheme)], scheme) {
		return nil
	}
	rest := strings.TrimSpace(s[len(scheme):])
	out := map[string]string{}
	// Разбираем list of key=value через запятую, уважая кавычки.
	pos := 0
	for pos < len(rest) {
		// skip ws/commas
		for pos < len(rest) && (rest[pos] == ' ' || rest[pos] == '\t' || rest[pos] == ',') {
			pos++
		}
		if pos >= len(rest) {
			break
		}
		// читаем key
		keyStart := pos
		for pos < len(rest) && rest[pos] != '=' && rest[pos] != ',' {
			pos++
		}
		key := strings.TrimSpace(rest[keyStart:pos])
		if key == "" {
			// нет смысла продолжать с пустым ключом — пропускаем символ.
			if pos < len(rest) {
				pos++
			}
			continue
		}
		if pos >= len(rest) || rest[pos] != '=' {
			// одиночный токен без значения — игнорируем.
			continue
		}
		pos++ // skip '='
		// skip whitespace before value
		for pos < len(rest) && (rest[pos] == ' ' || rest[pos] == '\t') {
			pos++
		}
		// читаем value: либо quoted-string, либо token до запятой.
		var val string
		if pos < len(rest) && rest[pos] == '"' {
			pos++ // skip opening quote
			var b strings.Builder
			for pos < len(rest) {
				c := rest[pos]
				if c == '\\' && pos+1 < len(rest) {
					b.WriteByte(rest[pos+1])
					pos += 2
					continue
				}
				if c == '"' {
					pos++ // skip closing quote
					break
				}
				b.WriteByte(c)
				pos++
			}
			val = b.String()
		} else {
			valStart := pos
			for pos < len(rest) && rest[pos] != ',' {
				pos++
			}
			val = strings.TrimSpace(rest[valStart:pos])
		}
		out[strings.ToLower(key)] = val
	}
	return out
}
