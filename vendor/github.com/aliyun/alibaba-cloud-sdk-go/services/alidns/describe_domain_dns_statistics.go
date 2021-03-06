package alidns

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// DescribeDomainDnsStatistics invokes the alidns.DescribeDomainDnsStatistics API synchronously
// api document: https://help.aliyun.com/api/alidns/describedomaindnsstatistics.html
func (client *Client) DescribeDomainDnsStatistics(request *DescribeDomainDnsStatisticsRequest) (response *DescribeDomainDnsStatisticsResponse, err error) {
	response = CreateDescribeDomainDnsStatisticsResponse()
	err = client.DoAction(request, response)
	return
}

// DescribeDomainDnsStatisticsWithChan invokes the alidns.DescribeDomainDnsStatistics API asynchronously
// api document: https://help.aliyun.com/api/alidns/describedomaindnsstatistics.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) DescribeDomainDnsStatisticsWithChan(request *DescribeDomainDnsStatisticsRequest) (<-chan *DescribeDomainDnsStatisticsResponse, <-chan error) {
	responseChan := make(chan *DescribeDomainDnsStatisticsResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.DescribeDomainDnsStatistics(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// DescribeDomainDnsStatisticsWithCallback invokes the alidns.DescribeDomainDnsStatistics API asynchronously
// api document: https://help.aliyun.com/api/alidns/describedomaindnsstatistics.html
// asynchronous document: https://help.aliyun.com/document_detail/66220.html
func (client *Client) DescribeDomainDnsStatisticsWithCallback(request *DescribeDomainDnsStatisticsRequest, callback func(response *DescribeDomainDnsStatisticsResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *DescribeDomainDnsStatisticsResponse
		var err error
		defer close(result)
		response, err = client.DescribeDomainDnsStatistics(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// DescribeDomainDnsStatisticsRequest is the request struct for api DescribeDomainDnsStatistics
type DescribeDomainDnsStatisticsRequest struct {
	*requests.RpcRequest
	EndDate      string `position:"Query" name:"EndDate"`
	UserClientIp string `position:"Query" name:"UserClientIp"`
	DomainName   string `position:"Query" name:"DomainName"`
	Lang         string `position:"Query" name:"Lang"`
	StartDate    string `position:"Query" name:"StartDate"`
}

// DescribeDomainDnsStatisticsResponse is the response struct for api DescribeDomainDnsStatistics
type DescribeDomainDnsStatisticsResponse struct {
	*responses.BaseResponse
	RequestId  string                                  `json:"RequestId" xml:"RequestId"`
	Statistics StatisticsInDescribeDomainDnsStatistics `json:"Statistics" xml:"Statistics"`
}

// CreateDescribeDomainDnsStatisticsRequest creates a request to invoke DescribeDomainDnsStatistics API
func CreateDescribeDomainDnsStatisticsRequest() (request *DescribeDomainDnsStatisticsRequest) {
	request = &DescribeDomainDnsStatisticsRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Alidns", "2015-01-09", "DescribeDomainDnsStatistics", "Alidns", "openAPI")
	return
}

// CreateDescribeDomainDnsStatisticsResponse creates a response to parse from DescribeDomainDnsStatistics response
func CreateDescribeDomainDnsStatisticsResponse() (response *DescribeDomainDnsStatisticsResponse) {
	response = &DescribeDomainDnsStatisticsResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
