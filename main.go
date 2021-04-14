// A wrapper to receive Prometheus Alerts from Alertmanager via webhook and forward them to BMC TrueSight Operations
// Management as event.
//
// Author: 	Patrick Mischler (patrick.mischler@itcorncepts.ch)
// Version: 0.2
// Status: experimental

// TODO - Documentation: enhance code documentation
// TODO - Enhance error handling
// TODO - implement caching mechanism

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Server struct {
		ListenPort     string `yaml:"listen-port"`
		PromMetricPort string `yaml:"prom-metric-port"`
		TrueSight      struct {
			TSPSServer   string `yaml:"tsps-server"`
			TSPSPort     string `yaml:"tsps-port"`
			TSIMServer   string `yaml:"tsim-server"`
			TSIMPort     string `yaml:"tsim-port"`
			TSCell       string `yaml:"ts-cell"`
			TSUser       string `yaml:"ts-user"`
			TSUserPw     string `yaml:"ts-user-pw"`
			TSTenant     string `yaml:"ts-tenant"`
			TSEventClass string `yaml:"ts-event-class"`
		}
	}
}

func NewConfig(configPath string) (*Config, error) {
	config := &Config{}
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

func ParseFlags() (string, error) {
	var configPath string

	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")

	flag.Parse()

	if err := ValidateConfigPath(configPath); err != nil {
		return "", err
	}

	return configPath, nil
}

type TSEventAttributes struct {
	CLASS         string `json:"CLASS"`
	Severity      string `json:"severity"`
	Msg           string `json:"msg"`
	McObjectClass string `json:"mc_object_class"`
	McObject      string `json:"mc_object"`
	McParameter   string `json:"mc_parameter"`
	McObjectURI   string `json:"mc_object_uri"`
}

func NewTSEventAttributes(CLASS string, severity string, msg string, mc_object_class string, mc_object string, mc_parameter string, mc_object_uri string) *TSEventAttributes {
	return &TSEventAttributes{CLASS: CLASS, Severity: severity, Msg: msg, McObjectClass: mc_object_class, McObject: mc_object, McParameter: mc_parameter, McObjectURI: mc_object_uri}
}

type TSEvent struct {
	EventSourceHostName  string             `json:"eventSourceHostName"`
	EventSourceIPAddress string             `json:"eventSourceIPAddress"`
	Attributes           *TSEventAttributes `json:"attributes"`
}

func NewTSEvent(eventSourceHostName string, eventSourceIPAddress string, attributes *TSEventAttributes) *TSEvent {
	return &TSEvent{EventSourceHostName: eventSourceHostName, EventSourceIPAddress: eventSourceIPAddress, Attributes: attributes}
}

type Labels struct {
	Alertname  string `json:"alertname"`
	Instance   string `json:"instance"`
	Job        string `json:"job"`
	Path       string `json:"path"`
	Prometheus string `json:"prometheus"`
	Severity   string `json:"severity"`
}

type Annotations struct {
	Description string `json:"description"`
}

type Alert struct {
	Status       string      `json:"status"`
	Labels       Labels      `json:"labels"`
	Annotations  Annotations `json:"annotations"`
	StartsAt     string      `json:"startsAt"`
	EndsAt       string      `json:"endsAt"`
	GeneratorURL string      `json:"generatorURL"`
	Fingerprint  string      `json:"fingerprint"`
}

type Alerts struct {
	Alerts []Alert `json:"alerts"`
}

type tstoken struct {
	authToken string
}

func (t *tstoken) getToken() string {
	return t.authToken
}

func (t *tstoken) setToken(token string) {
	t.authToken = token
}

func newTSToken(token string) *tstoken {
	return &tstoken{
		authToken: token,
	}
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func (config Config) Run() {
	fmt.Println("starting listening for prometheus alerts...")
	tsToken := newTSToken(GetTSToken(
		config.Server.TrueSight.TSPSServer,
		config.Server.TrueSight.TSPSPort,
		config.Server.TrueSight.TSUser,
		config.Server.TrueSight.TSUserPw,
		config.Server.TrueSight.TSTenant))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "404 not found.", http.StatusNotFound)
			return
		}

		if r.Method == "POST" {
			if !VerifyTSToken(tsToken.getToken(),
				config.Server.TrueSight.TSPSServer,
				config.Server.TrueSight.TSPSPort) {
				tsToken.setToken(GetTSToken(
					config.Server.TrueSight.TSPSServer,
					config.Server.TrueSight.TSPSPort,
					config.Server.TrueSight.TSUser,
					config.Server.TrueSight.TSUserPw,
					config.Server.TrueSight.TSTenant))
			}
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Fatal("Error reading response body", err)
			}

			var alerts Alerts
			if err := json.Unmarshal(body, &alerts); err != nil {
				ErrorLogger.Println("JSON unmarshaling has errors: ", err)
			}
			var events []*TSEvent
			for alert := range alerts.Alerts {
				//fmt.Println(alerts.Alerts[alert].Status)
				if alerts.Alerts[alert].Status == "firing" {
					tsEvent := NewTSEvent(alerts.Alerts[alert].Labels.Instance,
						"",
						NewTSEventAttributes(config.Server.TrueSight.TSEventClass,
							strings.ToUpper(alerts.Alerts[alert].Labels.Severity),
							alerts.Alerts[alert].Annotations.Description,
							alerts.Alerts[alert].Labels.Job,
							alerts.Alerts[alert].Labels.Path,
							alerts.Alerts[alert].Labels.Alertname,
							alerts.Alerts[alert].GeneratorURL))
					events = append(events, tsEvent)
				}
			}

			if events != nil {
				if SendEventToTS(tsToken.getToken(), config.Server.TrueSight.TSIMServer, config.Server.TrueSight.TSIMPort, config.Server.TrueSight.TSCell, events) {
					InfoLogger.Println("Event sent to TrueSight.")
					fmt.Fprintf(w, "Event(s) created")
				} else {
					WarningLogger.Println("Failed to send event(s) to TrueSight.")
					promAlertsCache.Add(RandomString(10), events, cache.DefaultExpiration)
					http.Error(w, "Something went wrong on the server!", http.StatusInternalServerError)
				}
			}
		}
	})
	fmt.Println("Server started at port " + config.Server.ListenPort)
	InfoLogger.Println("Server started at port " + config.Server.ListenPort)
	log.Fatal(http.ListenAndServe(":"+config.Server.ListenPort, nil))
}

func GetTSToken(tspsServer string, tspsPort string, tsUser string, tsUserPw string, tsTenant string) string {
	authToken := "undefined"
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tokenUrl := "https://" + tspsServer + ":" + tspsPort + "/tsws/api/v10.1/token"
	postData := map[string]string{"username": tsUser, "password": tsUserPw, "tenantName": tsTenant}
	postDataJson, err := json.Marshal(postData)

	if err != nil {
		log.Fatal("Error creating JSON Body: ", err)
	}

	retryCount := 0
	for {
		resp, err := http.Post(tokenUrl, "application/json", bytes.NewBuffer(postDataJson))
		if err != nil {
			ErrorLogger.Println("Error getting TS auth token: ", err)
			time.Sleep(10 * time.Second)
			retryCount++
		} else {
			rawData, _ := ioutil.ReadAll(resp.Body)
			InfoLogger.Println("Get TS auth token response: ", rawData)
			var data map[string]map[string]interface{}
			json.Unmarshal(rawData, &data)
			authToken = data["response"]["authToken"].(string)
			break
		}
	}
	return authToken
}

func VerifyTSToken(token string, tspsServer string, tspsPort string) bool {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tokenUrl := "https://" + tspsServer + ":" + tspsPort + "/tsws/api/v10.1/token"
	req, err := http.NewRequest("GET", tokenUrl, nil)
	if err != nil {
		log.Fatal("Error reading request. ", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("authToken", "authToken "+token)

	client := &http.Client{Timeout: time.Second * 10}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Unable to perform request: ", err)
	} else {
		defer resp.Body.Close()
		rawData, _ := ioutil.ReadAll(resp.Body)
		var data map[string]interface{}
		if err := json.Unmarshal(rawData, &data); err != nil {
			log.Fatal("Unable to transform alarm: ", err)
		}
		statusMsg := data["statusMsg"].(string)
		if statusMsg == "OK" {
			return true
		} else {
			return false
		}
	}
	return true
}

func SendEventToTS(token string, tsimServer string, tsimPort string, tsCell string, eventData []*TSEvent) bool {
	eventSendState := false
	eventUrl := "https://" + tsimServer + ":" + tsimPort + "/bppmws/api/Event/create?routingId=" + tsCell
	eventJSON, err := json.Marshal(eventData)
	if err != nil {
		log.Fatal(err)
	}

	InfoLogger.Println("Event ind JSON: ", string(eventJSON))
	//evBody := string(eventJSON)
	req, err := http.NewRequest("POST", eventUrl, bytes.NewBuffer(eventJSON))
	if err != nil {
		log.Fatal("Error reading request. ", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "authToken "+token)

	client := &http.Client{Timeout: time.Second * 10}

	resp, err := client.Do(req)
	if err != nil {
		ErrorLogger.Println(err)
	} else {
		InfoLogger.Println(resp)
		eventSendState = true
	}
	return eventSendState
}

func Heartbeat() {
	// Heartbeat for self-monitoring
	InfoLogger.Println("starting heartbeat...")
	value := 0
	for true {
		promalToTSOMHeartbeat.Set(float64(value))
		if value == 0 {
			value = 100
		} else {
			value = 0
		}
		InfoLogger.Println("Heartbeat value in loop: ", value)
		time.Sleep(1 * time.Minute)
	}
}

func InitLogging(logName string) {
	file, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal("Unable to create logfile: ", err)
	}

	InfoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(file, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Initialize Loggers
var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
)

// Initiate Prometheus Alerts Cache
var promAlertsCache = cache.New(60*time.Minute, 90*time.Minute)
var promalToTSOMHeartbeat = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "prometheus_alerts_to_tsom_heartbeat",
	Help: "Prometheus Alerts to TrueSight",
})

func main() {
	// Initialize logging
	logFileName := "promalert2bmctsom.log"
	InitLogging(logFileName)
	InfoLogger.Println("Prometheus Alert to BMC TSOM Wrapper started")

	cfgPath, err := ParseFlags()
	if err != nil {
		log.Fatal("Unable to read config file: ", err)
	}
	cfg, err := NewConfig(cfgPath)
	if err != nil {
		log.Fatal("Unable to read config file: ", err)
	}
	// start listening for Prometheus Alerts
	go cfg.Run()

	// Initialize prometheus metering
	InfoLogger.Println("starting heartbeat")

	//fmt.Println("starting heartbeat")
	go Heartbeat()
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":"+cfg.Server.PromMetricPort, nil)
	time.Sleep(1 * time.Second)

}
