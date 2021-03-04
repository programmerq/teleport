---
authors: Joel Wejdenstal (jwejdenstal@goteleport.com)
state: draft
---

# RFD 19 - Event Fetch API with Pagination

## What

Implement a new API based on the current API for fetching events
but with full pagination support in form of a `StartKey: string` parameter that allows the client to search from a specific point in the event stream instead of starting at the first event of the start date.

## Why

This RFC was sparked from issue [#5435](https://github.com/gravitational/teleport/issues/5435).
The primary motivation for this RFD is that clients are at the moment not able to fetch an event stream between two dates incrementally with multiple API calls.

Such functionality requires the client to be able to specify a point in the event stream from where the server will start searching forward from. Currently no such parameter exists which means the server will always start returning events from the start of the stream.

## Details

The current API for event fetch and search is over (https://github.com/gravitational/teleport/blob/master/lib/auth/apiserver.go#L246) plain HTTPS and not GRPC and runs on the authentication server.

I propose implementing a new GRPC API endpoint that replaces and deprecates the old HTTP API endpoint. The old API endpoint should be kept as is but documentation should mention that it is deprecated and advise clients to use the new API.

### Parameters and Response

´´´protobuf
message GetEventsRequest {
   // Namespace, if not set, defaults to 'default'
   Namespace string
   StartDate Timestamp
   EndDate Timestamp
   // EventType is optional, if not set, returns all events.
   // Current DynamoDB implementation is incorrect, it filters out events on the client
   // Instead it should activate Scan method to return the full set.
   // Check the behavior for firebase
   EventType string
   Limit int64
   StartKey string // When supplied the search will resume from the last key
}
´´´

´´´protobuf
message GetSessionEventsRequest {
   // SessionID is a required valid session ID
   SessionID string
   // EventType if set will look for an event type
   EventType string
   Limit int64
   StartKey string // When supplied the search will resume from the last key
}
´´´

´´´protobuf
message Events { 
    Items repeated oneof Event
    LastKey string // the key of the last event if the returned set did not contain all events found i.e limit < actual amount. this is the key clients can supply in another API request to continue fetching events from the previous last position
}
´´´