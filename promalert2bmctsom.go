// A wrapper to receive Prometheus Alerts from Alertmanager via webhook and forward them to BMC TrueSight Operations
// Management as event.
//
// Author: 	Patrick Mischler (patrick.mischler@itcorncepts.ch)
// Version: 0.1
// Status: experimental

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	Server struct {
		ListenPort string `yaml:"listen-port"`
		TrueSight  struct {
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

func (config Config) Run() {
	tsToken := newTSToken(GetTSToken(
		config.Server.TrueSight.TSPSServer,
		config.Server.TrueSight.TSPSPort,
		config.Server.TrueSight.TSUser,
		config.Server.TrueSight.TSUserPw,
		config.Server.TrueSight.TSTenant))
	//fmt.Printf("Token has been set: %s", tsToken.getToken())
	//http.HandleFunc("/", AlertHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "404 not found.", http.StatusNotFound)
			return
		}

		//fmt.Printf("Token: %s", tsToken.getToken())

		if r.Method == "POST" {
			if !VerifyTSToken(tsToken.getToken(),
				config.Server.TrueSight.TSPSServer,
				config.Server.TrueSight.TSPSPort) {
				//fmt.Println("Token verification failed. Obtaining new token.")
				tsToken.setToken(GetTSToken(
					config.Server.TrueSight.TSPSServer,
					config.Server.TrueSight.TSPSPort,
					config.Server.TrueSight.TSUser,
					config.Server.TrueSight.TSUserPw,
					config.Server.TrueSight.TSTenant))
			}
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				print(err)
			}

			var alerts Alerts
			json.Unmarshal(body, &alerts)
			events := []*TSEvent{}
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

			//eventAttributes := NewTSEventAttributes("EVENT", "WARNING","Test Message", "Huba",
			//	"Test", "Test")
			//eventData := NewTSEvent("Test","", eventAttributes)

			//events = append(events, eventData)
			if events != nil {
				SendEventToTS(tsToken.getToken(), config.Server.TrueSight.TSIMServer, config.Server.TrueSight.TSIMPort, config.Server.TrueSight.TSCell, events)
			}

			//fmt.Print(string(body))
		}
	})
	fmt.Println("Server started at port " + config.Server.ListenPort)
	log.Fatal(http.ListenAndServe(":"+config.Server.ListenPort, nil))
}

func main() {
	cfgPath, err := ParseFlags()
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := NewConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Run()
}

func GetTSToken(tspsServer string, tspsPort string, tsUser string, tsUserPw string, tsTenant string) string {
	authToken := "undefined"
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tokenUrl := "https://" + tspsServer + ":" + string(tspsPort) + "/tsws/api/v10.1/token"
	postData := map[string]string{"username": tsUser, "password": tsUserPw, "tenantName": tsTenant}
	postDataJson, err := json.Marshal(postData)

	if err != nil {
		log.Fatal(err)
	}

	resp, err := http.Post(tokenUrl, "application/json",
		bytes.NewBuffer(postDataJson))

	if err != nil {
		log.Fatal(err)
	} else {
		defer resp.Body.Close()
		rawData, _ := ioutil.ReadAll(resp.Body)
		var data map[string]map[string]interface{}
		json.Unmarshal(rawData, &data)
		/*if err != nil {
			log.Fatal(err)
		}*/
		authToken = data["response"]["authToken"].(string)
		//fmt.Println(authToken)
	}
	//fmt.Println("Auth Token is: " + authToken)
	return authToken
}

func VerifyTSToken(token string, tspsServer string, tspsPort string) bool {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tokenUrl := "https://" + tspsServer + ":" + string(tspsPort) + "/tsws/api/v10.1/token"
	//fmt.Println("Token: " + token)
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
		log.Fatal(err)
	} else {
		defer resp.Body.Close()
		rawData, _ := ioutil.ReadAll(resp.Body)
		var data map[string]interface{}
		json.Unmarshal(rawData, &data)
		//statusCode := data["statusCode"].(string)
		statusMsg := data["statusMsg"].(string)
		//fmt.Println("Status Code: " + statusCode)
		//fmt.Println("Status Message: " + statusMsg)
		if statusMsg == "OK" {
			return true
		} else {
			return false
		}
	}
	return true
}

func SendEventToTS(token string, tsimServer string, tsimPort string, tsCell string, eventData []*TSEvent) bool {
	eventUrl := "https://" + tsimServer + ":" + tsimPort + "/bppmws/api/Event/create?routingId=" + tsCell
	eventJSON, err := json.Marshal(eventData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(eventJSON))
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
		log.Fatal(err)
	}
	fmt.Println(resp)
	return true
}
