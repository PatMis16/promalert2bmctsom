# Prometheus Alerts to BMC TrueSight Operations Management

This Go-program is an example of a wrapper to integrate Prometheus alerts into BMC TrueSight Operations 
Management.
The program starts a simple webserver which awaits Prometheus alerts sent from the Prometheus Alertmanager
via a webhook receiver.

## Prerequisites
On some Linux platforms musl libc (https://musl.libc.org/) is required in order to run the binary. For example: On Ubuntu you can
install musl with `sudo apt install musl`.

## Wrapper Configuration
The Go programm (wrapper) reads a YAML configuration file. The configuration file contains information about the 
listening port of the wrapper and data to connect to TrueSight.

```yaml
server:
  listen-port: <Listen Port e.g. 9595>
  truesight:
    tsps-server: "<TSPS Server Name>"
    tsps-port: <TSPS Server Port e.g. 8043>
    tsim-server: "<TSIM Server Name>"
    tsim-port: <TSIM Server Port e.g. 8443
    ts-cell: "<Cell Name>"
    ts-user: "<TS User>"
    ts-user-pw: "<TS User Password>"
    ts-tenant: "<Tenant Name>"
    ts-event-class: "<Eventclass e.g. EVENT or PROMETHEUS>"
```

As this is an example, the program will terminate if either the TSPS or the TSIM cannot be reached. For use in a 
production environment, the error handling has to be enhanced. 

The program can be started without any arguments, then a `config.yaml` is expected to be present in the directory where
the program is located. With the argument `-config <config file path>` a configuration file can be specified. 

## Prometheus Alertmanager Configuration
In the configuration file of the Prometheus Alertmanager, a webhook receiver has to be configured:

```yaml
receivers:
- name: bmctsom-receiver
  webhook_configs:
  - url: http://<server where you start the wrapper>:<port of the wrapper>
```

## TrueSight Operations Management Configuration
All you need is a User which is allowed to perform REST API Calls to the TrueSight Presentation and Infrastructure 
Management Server. 
Allthough you can send the alerts from Prometheus Alertmanager to TSOM as eventclass EVENT, it is recommended to create
a separate event class to simplyfy event processing. An example for an event class is displayed below. Whithin this 
class some custom event slots are defined to hold information of the Prometheus alert ind the prometheus terminology.  

```mrl
MC_EV_CLASS:
   PROMETHEUS ISA EVENT
   DEFINES
   {
      prometheus_alertname : STRING;
      prometheus_instance: STRING;
      prometheus_job: STRING;
      prometheus_path: STRING;
      prometheus_server: STRING;
      prometheus_original_severity: STRING;
      prometheus_annotation_description: STRING;
      prometheus_alert_fingerprint: STRING;
   };
END
```
