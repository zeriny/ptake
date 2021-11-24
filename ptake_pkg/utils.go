package ptake_pkg

func removeDuplicates(l []string) (res []string) {
	cache := make(map[string]int)
	for i := range l {
		_, ok := cache[l[i]]
		if ok {
			continue
		} else {
			cache[l[i]] = 1
		}
	}
	for k, _ := range cache {
		res = append(res, k)
	}
	return res
}

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
