package common

import (
	"github.com/rclone/go-proton-api"

	"github.com/go-resty/resty/v2"
)

// Applies to all API calls made by the shared proton.Manager.
const defaultAPIRequestRetryCount = 3

type preRequestHookClient interface {
	AddPreRequestHook(resty.RequestMiddleware)
}

func attachDriveSDKHeaderHook(client preRequestHookClient, driveSDKVersion string) {
	if driveSDKVersion == "" {
		return
	}

	client.AddPreRequestHook(func(_ *resty.Client, req *resty.Request) error {
		req.SetHeader("x-pm-drive-sdk-version", driveSDKVersion)
		return nil
	})
}

func getProtonManager(appVersion string, userAgent string) *proton.Manager {
	/* Notes on API calls: if the app version is not specified, the api calls will be rejected. */
	options := []proton.Option{
		proton.WithAppVersion(appVersion),
		proton.WithRetryCount(defaultAPIRequestRetryCount),
		proton.WithUserAgent(userAgent),
	}
	m := proton.New(options...)

	return m
}
