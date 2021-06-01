using System;
using System.Threading.Tasks;
using TestContainers.Core.Builders;
using TestContainers.Core.Containers;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Persistence
{
    public class DynamoDBContainerFixture : IAsyncLifetime
    {
        private readonly bool disableTestContainers;

        public DynamoDBContainerFixture()
        {
            disableTestContainers = Convert.ToBoolean(Environment.GetEnvironmentVariable("DISABLE_TESTCONTAINERS"));

            if (disableTestContainers)
            {
                string hostname = Environment.GetEnvironmentVariable("DYNAMODB_HOSTNAME");
                if (hostname == null)
                {
                    HostName = "localhost";
                }
                else
                {
                    HostName = hostname;
                }

                ServiceUrl = $"http://{HostName}:8000";
            }
            else
            {
                DynamoDbContainer = new GenericContainerBuilder<Container>()
                    .Begin()
                    .WithImage("amazon/dynamodb-local:latest")
                    .WithExposedPorts(8000)
                    .WithPortBindings((8000, 8000))
                    .Build();

                ServiceUrl = $"http://{DynamoDbContainer.GetDockerHostIpAddress()}:{DynamoDbContainer.ExposedPorts[0]}";
            }
        }

        public string ServiceUrl { get; }

        public string HostName { get; }

        private Container DynamoDbContainer { get; }

        public Task InitializeAsync()
        {
            return disableTestContainers ? Task.Delay(0) : DynamoDbContainer.Start();
        }

        public Task DisposeAsync()
        {
            return disableTestContainers ? Task.Delay(0) : DynamoDbContainer.Stop();
        }
    }
}
