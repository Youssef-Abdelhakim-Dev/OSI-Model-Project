Full OSI Layer Analyzer
🟢 Overview

This project is built with PowerShell 5.1 and is designed to analyze any website across all OSI layers (1 → 7) + Extra Layer.
The script performs a sequential analysis for each URL and collects key network and application information such as:

Latency (Ping)

Bandwidth

TCP/UDP Connections

TLS Handshake

HTTP/HTTPS Response

JSON Validation

HTML Response

Optional Screenshot

Processes connected to the network

The results are saved in TXT, JSON, CSV, and HTML files inside a dedicated folder.

⚡ Features

Layer 1 – Physical

Detects all active network adapters

Displays adapter speed and status

Layer 2 – Data Link

Detects default gateway

Shows ARP table entry for the gateway

Layer 3 – Network (DNS + Routing)

Resolves IP addresses of the target website

Tests TCP port 443 connectivity

Layer 4 – Transport

Lists established TCP connections

Displays LocalPort, RemotePort, and PID

Layer 5 – Session

Counts active TCP sessions

Layer 6 – Presentation (TLS)

Performs TLS handshake

Checks HTTPS certificate validity

Layer 7 – Application

Performs HTTP/HTTPS requests

Measures bandwidth (KB/s)

Saves HTML Response

Optional JSON validation

Extra Layer – Processes

Lists processes connected to the internet (Port 443)

Optional Screenshot

Captures a snapshot of the website

Reports

TXT Log

JSON Report

CSV File

HTML Response

Screenshot (optional)

Popup Notification

Alerts when the analysis of a website is completed
