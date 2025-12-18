package stats

import "slices"

func computeAverage(times []int64) float64 {
	if len(times) == 0 {
		return 0
	}
	var total int64
	for _, t := range times {
		total += t
	}

	return float64(total) / float64(len(times)) / 1e6
}

func computePercentiles(times []int64) map[string]float64 {
	if len(times) == 0 {
		return map[string]float64{
			"P50": 0,
			"P90": 0,
			"P95": 0,
			"P99": 0,
		}
	}

	// Make a copy to avoid mutating the input slice
	sorted := make([]int64, len(times))
	copy(sorted, times)
	slices.Sort(sorted)

	percentiles := map[string]float64{}
	percentiles["P50"] = float64(sorted[len(sorted)/2]) / 1e6
	percentiles["P90"] = float64(sorted[int(0.9*float64(len(sorted)))]) / 1e6
	percentiles["P95"] = float64(sorted[int(0.95*float64(len(sorted)))]) / 1e6
	percentiles["P99"] = float64(sorted[int(0.99*float64(len(sorted)))]) / 1e6

	return percentiles
}
