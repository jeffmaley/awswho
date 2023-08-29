import boto3
import json
import logging
import argparse
import datetime


logging.basicConfig(filename='temp.log', 
                    level=logging.INFO, 
                    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')


access_key_pairs = []

def get_regions() -> list:
    ec2 = boto3.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions()
    regions = []
    for region in response.get("Regions"):
        #print(region.get("RegionName"))
        regions.append(region.get("RegionName"))
    return regions


def lookup(region_name: str, event_name: str, users_only=False, start_time=None, end_time=None):
    right_now = datetime.datetime.now()
    if start_time is not None:
        start_time_delta = datetime.timedelta(hours=int(start_time))
        fmt_start_time = right_now - start_time_delta
    else:
        start_time_delta = datetime.timedelta(hours=24)
        fmt_start_time = right_now - start_time_delta
    if end_time is not None:
        end_time_delta = datetime.timedelta(hours=int(end_time))
        fmt_end_time = right_now - end_time_delta
    else:
        end_time_delta = datetime.timedelta(hours=24)
        fmt_end_time = right_now - end_time_delta
    ct = boto3.client("cloudtrail", region_name=region_name)
#    lookup_response = ct.lookup_events(
#            LookupAttributes=[
#                {'AttributeKey': 'EventName',
#                'AttributeValue': event_name
#                 }
#                ],
#            StartTime=fmt_start_time,
#            EndTime=fmt_end_time
#            )
#    event_response = []
#    for event in lookup_response.get("Events"):
#        event_response.append(event)
#    next_token = lookup_response.get("NextToken")
    next_token = "NoValue"
    old_token = None
    while next_token is not None:
        print(f"next_token = {next_token}")
        lookup_response = ct.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'EventName',
                    'AttributeValue': event_name
                    }
                ],
            StartTime=fmt_start_time,
            EndTime=fmt_end_time
        )
        old_token = next_token
        next_token = lookup_response.get("NextToken")
        if old_token == next_token:
            next_token = None
        for event in lookup_response.get("Events"):
            print(event)
            event = parse_events(event, event_name, users_only=users_only)
            yield event
    #events = []
    #event_response.append(event)
    #for event in event_response:
        #event = parse_events(event, event_name, users_only=users_only)
        #events.append(event)
        #return #events
        #yield event


def parse_events(event: dict, event_name: str, users_only=False):
    event_return = {"invokedBy": None,
                    "principalId": None,
                    "sourceArn": None,
                    "sourceAccessKeyId": None}
    if event.get("CloudTrailEvent") is not None:
        event_data = json.loads(event.get('CloudTrailEvent'))
        event_return["eventName"] = event_name
        event_return["eventTime"] = event_data.get("eventTime")
        event_return["CloudTrailEvent"] = event_data
        if event_data.get("responseElements") and event_data.get("responseElements").get("credentials"):
            event_return["destAccessKeyId"] = event_data.get("responseElements").get("credentials").get("accessKeyId")
            event_return["expiration"] = event_data.get("responseElements").get("credentials").get("expiration")
        else:
            event_return["destAccessKeyId"] = None
            event_return["expiration"] = None
        if event_name == "AssumeRole":
            #print(f"{event.get('CloudTrailEvent')}")
            if event_data.get("userIdentity").get("type") == "AWSService":
                if users_only is False:
                    event_return["invokedBy"] = event_data.get("userIdentity").get("invokedBy")
                else:
                    return None
                event_return["invokedBy"] = event_data.get("userIdentity").get("invokedBy")
            elif event_data.get("userIdentity").get("type") == "AssumedRole": 
                event_return["principalId"] = event_data.get("userIdentity").get("principalId")
                event_return["sourceArn"] = event_data.get("userIdentity").get("arn")
                event_return["sourceAccessKeyId"] = event_data.get("userIdentity").get("accessKeyId")
            else:
                pass
                #print("found AssumeRole")
                #print(event_data)
            if event_data.get("requestParameters"):
                event_return["destinationRole"] = event_data.get("requestParameters").get("roleArn")
                event_return["destinationRoleSessionName"] = event_data.get("requestParameters").get("roleSessionName")
                event_return["destinationDurationSeconds"] = event_data.get("requestParameters").get("durationSeconds")
            access_key_pairs.append((event_return.get("sourceAccessKeyId"),event_return.get("destAccessKeyId")))
            if event_return.get("destinationRole"):
                return event_return
            else:
                return None
        elif event_name == "ConsoleLogin":
            if event_data.get("userIdentity").get("type") == "AssumedRole":
                event_return["principalId"] = event_data.get("userIdentity").get("principalId")
                event_return["sourceArn"] = event_data.get("userIdentity").get("arn")
            return event_return
        else:
            pass
    else:
        logging.warn(f"Event missing CloudTrailEvent - {event}")
        return None


def write_csv(events):
    cols = ["invokedBy", "principalId", "sourceArn", "sourceAccessKeyId", "destinationRole", "destinationRoleSessionName", "destinationDurationSeconds", "destAccessKeyId", "expiration", "eventName"]
    o = open("awswho.csv", "a")
    for ele in cols:
        o.write(f"{ele},")
    o.write("\n")
    for event in events:
        if event is not None:
            print(event)
            for ele in cols:
                if event.get(ele):
                    o.write(f"{event.get(ele)},")
                else:
                    o.write("None,")
            o.write("\n")
    o.close()


def main(args):
    is_debug = args.debug
    event_names = ["AssumeRole", "ConsoleLogin", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"]
    #event_names = ["ConsoleLogin"]
    regions = get_regions()
    for event_name in event_names:
        print(f"Checking for {event_name}")
        for region in regions:
            print(f"Checking {region}")
            events = lookup(region, event_name, users_only=args.users_only, start_time=args.start_time, end_time=args.end_time)
            if events != []:
                #for event in events:
                for event in lookup(region, event_name, users_only=args.users_only, start_time=args.start_time, end_time=args.end_time):
                    #if event is not None and event.get("principalId") is not None:
                    if event is not None:
                        print("\n")
                        for k,v in event.items():
                            if v is not None:
                                if k != "CloudTrailEvent":
                                    print(f"{k}: {v}")
                                if k == "CloudTrailEvent" and is_debug:
                                    print(f"{k}: {v}")
                #write_csv(events)
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--users_only', action="store_true", default=False)
    parser.add_argument('-d', '--debug', action="store_true", default=False)
    parser.add_argument('-s', '--start_time')
    parser.add_argument('-e', '--end_time')
    args = parser.parse_args()
    main(args)
