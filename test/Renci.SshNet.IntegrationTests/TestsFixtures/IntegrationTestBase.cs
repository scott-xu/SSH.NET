﻿using Microsoft.Extensions.Logging;

namespace Renci.SshNet.IntegrationTests.TestsFixtures
{
    /// <summary>
    /// The base class for integration tests
    /// </summary>
    public abstract class IntegrationTestBase
    {
        private readonly InfrastructureFixture _infrastructureFixture;
        private readonly ILogger _logger;

        /// <summary>
        /// The SSH Server host name.
        /// </summary>
        public string SshServerHostName
        {
            get
            {
                return _infrastructureFixture.SshServerHostName;
            }
        }

        /// <summary>
        /// The SSH Server host name
        /// </summary>
        public ushort SshServerPort
        {
            get
            {
                return _infrastructureFixture.SshServerPort;
            }
        }

        /// <summary>
        /// The admin user that can use SSH Server.
        /// </summary>
        public SshUser AdminUser
        {
            get
            {
                return _infrastructureFixture.AdminUser;
            }
        }

        /// <summary>
        /// The normal user that can use SSH Server.
        /// </summary>
        public SshUser User
        {
            get
            {
                return _infrastructureFixture.User;
            }
        }

        protected IntegrationTestBase()
        {
            _infrastructureFixture = InfrastructureFixture.Instance;
            _logger = SshNetLoggingConfiguration.LoggerFactory.CreateLogger(GetType());
            _logger.LogDebug("SSH Server: {Host}:{Port}",
                _infrastructureFixture.SshServerHostName,
                _infrastructureFixture.SshServerPort);
        }

        /// <summary>
        /// Creates the test file.
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <param name="size">Size in megabytes.</param>
        protected void CreateTestFile(string fileName, int size)
        {
            using (var testFile = File.Create(fileName))
            {
                var random = new Random();
                for (int i = 0; i < 1024 * size; i++)
                {
                    var buffer = new byte[1024];
                    random.NextBytes(buffer);
                    testFile.Write(buffer, 0, buffer.Length);
                }
            }
        }
    }
}
