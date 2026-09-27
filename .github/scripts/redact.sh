#!/usr/bin/env bash
# Strips tenant identifiers from Terraform output before it reaches a public
# log, step summary or pull request comment. Reads stdin, writes stdout.
#
# This repository is public, so its logs are too. Raw plan output holds the
# tenant ID, object IDs of policies and groups, and the state storage account
# name. GitHub's secret masking is the second layer; this is the first.
{ grep -vE 'Refreshing state|Reading\.\.\.|Read complete|Still reading|Acquiring state lock|Releasing state lock' || true; } \
  | sed -E \
      -e 's/[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}/<guid>/g' \
      -e 's/[A-Za-z0-9-]+\.onmicrosoft\.com/<tenant-domain>/g' \
      -e 's/sttfstate[a-z0-9]+/<state-storage>/g' \
      -e 's#https://[A-Za-z0-9./_-]+#<url>#g'
