﻿using System;

using Renci.SshNet.Common;

namespace Renci.SshNet.Connection
{
    /// <summary>
    /// Represents an SSH identification.
    /// </summary>
    public sealed class SshIdentification
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SshIdentification"/> class with the specified protocol version
        /// and software version.
        /// </summary>
        /// <param name="protocolVersion">The SSH protocol version.</param>
        /// <param name="softwareVersion">The software version of the implementation.</param>
        /// <exception cref="ArgumentNullException"><paramref name="protocolVersion"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="softwareVersion"/> is <see langword="null"/>.</exception>
        public SshIdentification(string protocolVersion, string softwareVersion)
            : this(protocolVersion, softwareVersion, comments: null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SshIdentification"/> class with the specified protocol version,
        /// software version and comments.
        /// </summary>
        /// <param name="protocolVersion">The SSH protocol version.</param>
        /// <param name="softwareVersion">The software version of the implementation.</param>
        /// <param name="comments">The comments.</param>
        /// <exception cref="ArgumentNullException"><paramref name="protocolVersion"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="softwareVersion"/> is <see langword="null"/>.</exception>
        public SshIdentification(string protocolVersion, string softwareVersion, string comments)
        {
            ThrowHelper.ThrowIfNull(protocolVersion);
            ThrowHelper.ThrowIfNull(softwareVersion);

            ProtocolVersion = protocolVersion;
            SoftwareVersion = softwareVersion;
            Comments = comments;
        }

        /// <summary>
        /// Gets the software version of the implementation.
        /// </summary>
        /// <value>
        /// The software version of the implementation.
        /// </value>
        /// <remarks>
        /// This is primarily used to trigger compatibility extensions and to indicate
        /// the capabilities of an implementation.
        /// </remarks>
        public string SoftwareVersion { get; }

        /// <summary>
        /// Gets the SSH protocol version.
        /// </summary>
        /// <value>
        /// The SSH protocol version.
        /// </value>
        public string ProtocolVersion { get; }

        /// <summary>
        /// Gets the comments.
        /// </summary>
        /// <value>
        /// The comments, or <see langword="null"/> if there are no comments.
        /// </value>
        /// <remarks>
        /// <see cref="Comments"/> should contain additional information that might be useful
        /// in solving user problems.
        /// </remarks>
        public string Comments { get; }

        /// <summary>
        /// Returns the SSH identification string.
        /// </summary>
        /// <returns>
        /// The SSH identification string.
        /// </returns>
        public override string ToString()
        {
            var identificationString = "SSH-" + ProtocolVersion + "-" + SoftwareVersion;

            if (Comments != null)
            {
                identificationString += " " + Comments;
            }

            return identificationString;
        }
    }
}
