package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"gorm.io/gorm"
)

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type DomainStats struct {
	Domain      string  `json:"domain"`
	TotalPings  int64   `json:"total_pings"`
	SuccessRate float64 `json:"success_rate"`
	AvgRTT      float64 `json:"avg_rtt"`
}

type TimeSeriesData struct {
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	Value     float64   `json:"value"`
}

type IPDistribution struct {
	FailedIPs      int64 `json:"failed_ips"`
	HighLatencyIPs int64 `json:"high_latency_ips"`
	GoodIPs        int64 `json:"good_ips"`
}

type TotalStats struct {
	TotalFailedIPs int64 `json:"total_failed_ips"`
	TotalIPs       int64 `json:"total_ips"`
}

func setupRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	// 允许跨域
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// 设置静态文件目录
	r.Static("/static", "./static")

	// 根路由提供 charts.html
	r.GET("/", func(c *gin.Context) {
		// 读取 HTML 文件内容
		content, err := os.ReadFile("static/charts.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading file")
			return
		}

		// 设置内容类型为 HTML
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(content))
	})

	// 获取所有域名列表
	r.GET("/api/domains", func(c *gin.Context) {
		var domains []string
		if err := db.Model(&PingResult{}).
			Distinct().
			Order("domain").
			Pluck("domain", &domains).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, domains)
	})

	// 获取指定时间范围内的统计数据
	r.GET("/api/stats", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")
		domain := c.Query("domain")

		query := db.Model(&PingResult{})
		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}
		if startTime != "" {
			query = query.Where("datetime(timestamp) >= datetime(?)", startTime)
		}
		if endTime != "" {
			query = query.Where("datetime(timestamp) <= datetime(?)", endTime)
		}

		var stats []DomainStats
		err := query.Select(`
			domain,
			COUNT(*) as total_pings,
			AVG(CASE WHEN success = 1 THEN 1.0 ELSE 0.0 END) * 100 as success_rate,
			AVG(CASE WHEN success = 1 THEN rtt ELSE 0 END) as avg_rtt
		`).Group("domain").Find(&stats).Error

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, stats)
	})

	// 获取响应时间趋势数据
	r.GET("/api/trend", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")
		domain := c.Query("domain")

		query := db.Model(&PingResult{}).Where("success = ?", true)
		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}
		if startTime != "" {
			query = query.Where("datetime(timestamp) >= datetime(?)", startTime)
		}
		if endTime != "" {
			query = query.Where("datetime(timestamp) <= datetime(?)", endTime)
		}

		var results []struct {
			TimestampStr string `gorm:"column:timestamp_str"`
			Domain       string
			RTT          float64
		}

		// 根据时间间隔分组，使用字符串格式
		timeFormat := "strftime('%Y-%m-%d %H:%M:00', datetime(timestamp, 'localtime')) as timestamp_str"
		err := query.Select(fmt.Sprintf("%s, domain, avg(rtt) as rtt", timeFormat)).
			Group("timestamp_str, domain").
			Order("timestamp_str").
			Find(&results).Error

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var timeSeriesData []TimeSeriesData
		loc, _ := time.LoadLocation("Asia/Shanghai")
		for _, r := range results {
			// 解析时间字符串
			timestamp, err := time.ParseInLocation("2006-01-02 15:04:05", r.TimestampStr, loc)
			if err != nil {
				continue // 跳过无效的时间格式
			}
			timeSeriesData = append(timeSeriesData, TimeSeriesData{
				Timestamp: timestamp,
				Domain:    r.Domain,
				Value:     r.RTT,
			})
		}

		c.JSON(http.StatusOK, timeSeriesData)
	})

	// 获取超时统计数据
	r.GET("/api/timeouts", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")
		domain := c.Query("domain")

		query := db.Model(&PingResult{}).Where("success = ?", false)
		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}
		if startTime != "" {
			query = query.Where("datetime(timestamp) >= datetime(?)", startTime)
		}
		if endTime != "" {
			query = query.Where("datetime(timestamp) <= datetime(?)", endTime)
		}

		var results []struct {
			TimestampStr string `gorm:"column:timestamp_str"`
			Domain       string
			Count        int64
		}

		timeFormat := "strftime('%Y-%m-%d %H:%M:00', datetime(timestamp, 'localtime')) as timestamp_str"
		err := query.Select(fmt.Sprintf("%s, domain, count(*) as count", timeFormat)).
			Group("timestamp_str, domain").
			Order("timestamp_str").
			Find(&results).Error

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var timeSeriesData []TimeSeriesData
		loc, _ := time.LoadLocation("Asia/Shanghai")
		for _, r := range results {
			// 解析时间字符串
			timestamp, err := time.ParseInLocation("2006-01-02 15:04:05", r.TimestampStr, loc)
			if err != nil {
				continue // 跳过无效的时间格式
			}
			timeSeriesData = append(timeSeriesData, TimeSeriesData{
				Timestamp: timestamp,
				Domain:    r.Domain,
				Value:     float64(r.Count),
			})
		}

		c.JSON(http.StatusOK, timeSeriesData)
	})

	// 获取最近的错误日志
	r.GET("/api/errors", func(c *gin.Context) {
		domain := c.Query("domain")
		limit := 10 // 默认返回最近10条错误

		query := db.Model(&PingResult{}).Where("success = ?", false)
		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}

		var results []PingResult
		err := query.Order("timestamp desc").Limit(limit).Find(&results).Error

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, results)
	})

	// 获取总体统计数据
	r.GET("/api/total-stats", func(c *gin.Context) {
		var stats TotalStats

		// 获取总IP数
		if err := db.Model(&PingResult{}).Select("COUNT(DISTINCT ip) as total_ips").Find(&stats).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 获取曾经失败过的IP总数
		if err := db.Model(&PingResult{}).
			Where("success = ?", false).
			Select("COUNT(DISTINCT ip) as total_failed_ips").
			Find(&stats).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, stats)
	})

	// 获取指定时间范围内的IP分布
	r.GET("/api/ip-distribution", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")
		domain := c.Query("domain")

		query := db.Model(&PingResult{})
		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}
		if startTime != "" {
			query = query.Where("datetime(timestamp) >= datetime(?)", startTime)
		}
		if endTime != "" {
			query = query.Where("datetime(timestamp) <= datetime(?)", endTime)
		}

		var distribution IPDistribution

		// 获取失败的IP数量
		subQuery := query.Session(&gorm.Session{})
		if err := subQuery.Where("success = ?", false).
			Select("COUNT(DISTINCT ip) as failed_ips").
			Find(&distribution).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 获取高延迟IP数量 (RTT > 50ms)
		subQuery = query.Session(&gorm.Session{})
		if err := subQuery.Where("success = ? AND rtt > ?", true, 50*time.Millisecond).
			Select("COUNT(DISTINCT ip) as high_latency_ips").
			Find(&distribution).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 获取正常IP数量
		subQuery = query.Session(&gorm.Session{})
		if err := subQuery.Where("success = ? AND rtt <= ?", true, 50*time.Millisecond).
			Select("COUNT(DISTINCT ip) as good_ips").
			Find(&distribution).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, distribution)
	})

	// 获取不可访问IP数量的时间序列数据
	r.GET("/api/failed-ips-trend", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")
		domain := c.Query("domain")

		start, _ := time.Parse(time.RFC3339, startTime)
		end, _ := time.Parse(time.RFC3339, endTime)
		duration := end.Sub(start)

		// 根据时间间隔选择不同的分组格式
		var timeFormat string
		if duration <= time.Hour {
			// 1小时内，按分钟分组
			timeFormat = "strftime('%Y-%m-%d %H:%M:00', datetime(timestamp, 'localtime')) as timestamp_str"
		} else {
			// 大于1小时，按小时分组
			timeFormat = "strftime('%Y-%m-%d %H:00:00', datetime(timestamp, 'localtime')) as timestamp_str"
		}

		// 构建基础查询
		query := db.Model(&PingResult{}).Where("success = ?", false)
		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}
		if startTime != "" {
			query = query.Where("datetime(timestamp) >= datetime(?)", startTime)
		}
		if endTime != "" {
			query = query.Where("datetime(timestamp) <= datetime(?)", endTime)
		}

		var results []struct {
			TimestampStr string `gorm:"column:timestamp_str"`
			Count        int64
		}

		err := query.Select(fmt.Sprintf("%s, COUNT(DISTINCT ip) as count", timeFormat)).
			Group("timestamp_str").
			Order("timestamp_str").
			Find(&results).Error

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 确保返回的是空数组而不是 null
		timeSeriesData := make([]TimeSeriesData, 0)

		// 转换数据
		loc, _ := time.LoadLocation("Asia/Shanghai")
		for _, r := range results {
			timestamp, err := time.ParseInLocation("2006-01-02 15:04:05", r.TimestampStr, loc)
			if err != nil {
				continue
			}
			timeSeriesData = append(timeSeriesData, TimeSeriesData{
				Timestamp: timestamp,
				Value:     float64(r.Count),
			})
		}

		c.JSON(http.StatusOK, timeSeriesData)
	})

	// 获取故障IP列表
	r.GET("/api/failed-ips", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")
		domain := c.Query("domain")

		query := db.Model(&PingResult{}).Where("success = ?", false)

		if domain != "" && domain != "all" {
			query = query.Where("domain = ?", domain)
		}
		if startTime != "" {
			query = query.Where("datetime(timestamp) >= datetime(?)", startTime)
		}
		if endTime != "" {
			query = query.Where("datetime(timestamp) <= datetime(?)", endTime)
		}

		var results []struct {
			Timestamp time.Time
			Domain    string
			IP        string
			RTT       time.Duration
			Error     string
		}

		err := query.Order("timestamp desc").Find(&results).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, results)
	})

	// 导出Excel数据
	r.GET("/api/export", func(c *gin.Context) {
		startTime := c.Query("start")
		endTime := c.Query("end")

		// 设置时区为中国时区
		loc, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load timezone"})
			return
		}

		query := db.Model(&PingResult{})
		if startTime != "" {
			start, _ := time.Parse(time.RFC3339, startTime)
			query = query.Where("timestamp >= ?", start)
		}
		if endTime != "" {
			end, _ := time.Parse(time.RFC3339, endTime)
			query = query.Where("timestamp <= ?", end)
		}

		var results []PingResult
		if err := query.Order("timestamp desc").Find(&results).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 创建新的Excel文件
		f := excelize.NewFile()
		defer f.Close()

		// 创建一个工作表
		sheetName := "监控数据"
		f.SetSheetName("Sheet1", sheetName)

		// 设置表头
		headers := []string{"时间", "域名", "IP", "协议", "是否成功", "延迟(ms)", "错误信息"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(sheetName, cell, header)
		}

		// 写入数据
		for i, result := range results {
			row := i + 2
			protocol := "IPv4"
			if result.IsIPv6 {
				protocol = "IPv6"
			}
			rttMs := ""
			if result.Success {
				rttMs = fmt.Sprintf("%.2f", float64(result.RTT.Microseconds())/1000.0)
			}

			// 转换时间到中国时区
			localTime := result.Timestamp.In(loc)

			values := []interface{}{
				localTime.Format("2006-01-02 15:04:05"),
				result.Domain,
				result.IP,
				protocol,
				result.Success,
				rttMs,
				result.Error,
			}

			for j, value := range values {
				cell, _ := excelize.CoordinatesToCellName(j+1, row)
				f.SetCellValue(sheetName, cell, value)
			}
		}

		// 调整列宽
		f.SetColWidth(sheetName, "A", "A", 20) // 时间列
		f.SetColWidth(sheetName, "B", "B", 20) // 域名列
		f.SetColWidth(sheetName, "C", "C", 15) // IP列
		f.SetColWidth(sheetName, "D", "D", 10) // 协议列
		f.SetColWidth(sheetName, "E", "E", 10) // 成功列
		f.SetColWidth(sheetName, "F", "F", 12) // 延迟列
		f.SetColWidth(sheetName, "G", "G", 30) // 错误信息列

		// 设置响应头
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=network_monitor_data_%s.xlsx",
			time.Now().In(loc).Format("20060102_150405")))

		// 写入响应
		if err := f.Write(c.Writer); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	})

	return r
}
