package com.myorg;

import software.constructs.Construct;
import software.amazon.awscdk.Stack;
import software.amazon.awscdk.StackProps;
import software.amazon.awscdk.services.s3.Bucket;
import software.amazon.awscdk.services.s3.BucketProps;
import software.amazon.awscdk.RemovalPolicy;
// import software.amazon.awscdk.Duration;
// import software.amazon.awscdk.services.sqs.Queue;

public class AwsStack extends Stack {
    public AwsStack(final Construct scope, final String id) {
        this(scope, id, null);
    }

    public AwsStack(final Construct scope, final String id, final StackProps props) {
        super(scope, id, props);

        String bucketName = System.getenv("S3_BUCKET_NAME");
        Bucket uploadBucket = new Bucket(this, "TeamSphereUploadBucket", BucketProps.builder()
            .bucketName(bucketName)
            .versioned(true)
            .removalPolicy(RemovalPolicy.DESTROY)
            .autoDeleteObjects(true)
            .build()
        );
    }
}
