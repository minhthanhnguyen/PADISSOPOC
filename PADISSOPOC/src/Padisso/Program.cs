using Amazon.CDK;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Padi.Services.Authentication
{
    sealed class Program
    {
        public static void Main(string[] args)
        {
            var app = new App();
            var pool = new PadiSsoPocStack(app, "PadiSsoPocStack", new StackProps
            {
                // If you don't specify 'env', this stack will be environment-agnostic.
                // Account/Region-dependent features and context lookups will not work,
                // but a single synthesized template can be deployed anywhere.

                // Uncomment the next block to specialize this stack for the AWS Account
                // and Region that are implied by the current CLI configuration.
                /*
                Env = new Amazon.CDK.Environment
                {
                    Account = System.Environment.GetEnvironmentVariable("CDK_DEFAULT_ACCOUNT"),
                    Region = System.Environment.GetEnvironmentVariable("CDK_DEFAULT_REGION"),
                }
                */

                // Uncomment the next block if you know exactly what Account and Region you
                // want to deploy the stack to.
                /*
                Env = new Amazon.CDK.Environment
                {
                    Account = "123456789012",
                    Region = "us-east-1",
                }
                */

                // For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html
            });

            // Separate stack so the API can be deployed, rolled back or torn down without
            // touching the pool. The pool is passed by reference rather than imported by
            // name, which makes CDK order the deployments and fail fast on a broken link.
            new PadiSsoApiStack(app, "PadiSsoApiStack", new PadiSsoApiStackProps
            {
                UserPool = pool.UserPool,
                UserPoolClient = pool.UserPoolClient,
            });

            app.Synth();
        }
    }
}
