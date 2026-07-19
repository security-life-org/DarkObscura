package parser

import "strconv"

func itoa(i int) string { return strconv.Itoa(i) }

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
