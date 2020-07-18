#!/bin/bash

set -e

export GOPATH=/opt/gopath
export WORKDIR=${GOPATH}/src/github.com/xixuejia/digital-wallet/fabric/gosdk

echo "Run test in binary mode"
export SAMPLE_CC_PATH=github.com/xixuejia/digital-wallet/fabric/chaincode/samplecc
export MARBLES_CC_PATH=github.com/xixuejia/digital-wallet/fabric/chaincode/marbles
export PATH=$PATH:`pwd`
go build

applicationCapability=V1_2
echo "#############################Create channels with channelNamePrefix########################"
./gosdk channel create -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml \
  --applicationCapability ${applicationCapability} --channelNamePrefix mychannel \
  --channelConsortium SampleConsortium \
  --channelOrgs org1,org2 --ordererName orderer.example.com \
  --iterationCount 2 --iterationInterval 0.1s --retryCount 5 --logLevel DEBUG

echo "#############################Create channels with channelNameList########################"
./gosdk channel create -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml \
  --applicationCapability ${applicationCapability} --channelNameList mychannel,testmychannel \
  --channelConsortium SampleConsortium \
  --channelOrgs org1,org2 --ordererName orderer.example.com \
  --iterationCount 2 --iterationInterval 0.1s --retryCount 5 --logLevel DEBUG

echo "#############################Join org1 into channels########################"
./gosdk channel join -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml --channelNamePrefix mychannel \
--peers peer0.org1.example.com --ordererName orderer.example.com \
--iterationCount 2 --iterationInterval 0.1s --retryCount 5 --logLevel DEBUG


echo "############################# Replace orderer addresses ########################"
./gosdk channel update -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml --channelNamePrefix mychannel \
  --prefixOffset 0 \
  --ordererOrgName ordererorg --ordererName orderer.example.com --peers peer0.org1.example.com \
  --ordererAddresses orderer.example.com:7050 \
  --batchTimeout 1s --maxMessageCount 200 --preferredMaxBytes 103802353 --anchorPeers peer0.org1.example.com:7051 \
  --iterationCount 1 --iterationInterval 2s --retryCount 5 --logLevel DEBUG

echo "#############################Query org1 channels########################"
./gosdk channel query -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml --channelName mychannel0 --logLevel INFO \
        --peers peer0.org1.example.com --iterationCount 1 --iterationInterval 0.1s --retryCount 5

echo "#############################Install chaincode samplecc on org1 peers########################"
./gosdk chaincode install -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml --chaincodeNamePrefix samplecc- \
  --chaincodeVersion v1 \
  --path ${SAMPLE_CC_PATH} --peers peer0.org1.example.com \
  --iterationCount 2 --iterationInterval 0.1s --retryCount 5

echo "#############################Instantiate chaincode samplecc-0 with policy on mychannel0########################"
# Instantiate cc on all peers
./gosdk chaincode instantiate -c ${WORKDIR}/fixtures/ConnectionProfile_org1.yaml --chaincodeName samplecc-0 \
  --chaincodeVersion v1 \
  --channelNamePrefix mychannel --prefixOffset 0 --path ${SAMPLE_CC_PATH} \
  --policyStr "OR ('Org1MSP.member','Org2MSP.member')" \
  --peers peer0.org1.example.com \
  --iterationCount 1 --iterationInterval 0.2s --retryCount 5
