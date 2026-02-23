{{- define "cert-manager-webhook-autodns.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "cert-manager-webhook-autodns.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "cert-manager-webhook-autodns.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "cert-manager-webhook-autodns.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "cert-manager-webhook-autodns.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cert-manager-webhook-autodns.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "cert-manager-webhook-autodns.selfSignedIssuer" -}}
{{ include "cert-manager-webhook-autodns.fullname" . }}-selfsign
{{- end }}

{{- define "cert-manager-webhook-autodns.rootCAIssuer" -}}
{{ include "cert-manager-webhook-autodns.fullname" . }}-ca
{{- end }}

{{- define "cert-manager-webhook-autodns.rootCACertName" -}}
{{ include "cert-manager-webhook-autodns.fullname" . }}-ca
{{- end }}

{{- define "cert-manager-webhook-autodns.servingCertName" -}}
{{ include "cert-manager-webhook-autodns.fullname" . }}-webhook-tls
{{- end }}
