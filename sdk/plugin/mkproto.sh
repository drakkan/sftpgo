#!/bin/bash

protoc notifier/proto/notifier.proto --go_out=plugins=grpc:../.. --go_out=../../..
protoc kms/proto/kms.proto --go_out=plugins=grpc:../.. --go_out=../../..


