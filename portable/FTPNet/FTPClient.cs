using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Tls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;

namespace FTPNet
{
    public class FTPClient
    {
        #region Events
        public event CommandSendEventHandler CommandSendEvent;
        public event AnswerReadEventHandler AnswerReadEvent;
        public event ConnectedEventHandler ConnectedEvent;
        public event DisconnectedEventHandler DisconnectedEvent;
        public event LoggedInEventHandler LoggedInEvent;
        public event CertifacteValidationEventHandler CertifacteValidationEvent;
        public event EventHandler CurrentWorkingDirectoryChangedEvent;
        #endregion

        public bool LogInAutomatic = true;
        public bool EnterPassiveModeAutomatic = true;
        public bool LoggedIn = false;

        private System.Text.Encoding _encoding = Encoding.UTF8;

        public List<string> SupportedCommands;
        public int ConnectionAttemps { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Server { get; set; }
        public int Port { get; set; }

        private string _realServer;
        internal OSType OS;

        public string History { get; private set; }

        private readonly List<FTPConnection> _connections;

        private bool _certificateAccepted = false;

        internal CertificateVerifyer CertificateVerifyer;
        private DataProtectionMode _protectionMode;

        private string _currentWorkingDirectory = string.Empty;
        public string CurrentWorkingDirectory
        {
            get
            {
                return _currentWorkingDirectory;
            }
            private set
            {
                _currentWorkingDirectory = value;
                if (CurrentWorkingDirectoryChangedEvent != null)
                    CurrentWorkingDirectoryChangedEvent(this, null);
            }
        }

        public SSLMode EncryptionMode { get; set; }
        public DataProtectionMode ProtectionMode { get; set; }

        public SSLValidationMode ValidationMode { get; set; }

        private int _connectionType;
        public int ConnectionType
        {
            get
            {
                return _connectionType;
            }
            set
            {
                _connectionType = value;
            }
        }

        public FTPClient()
        {
            _connections = new List<FTPConnection>();
            SupportedCommands = new List<string>();
            CertificateVerifyer = new CertificateVerifyer(_validateServerCertificate);
            _connections = new List<FTPConnection>();
        }

        public async Task<bool> Connect()
        {
            //disconnect at first
            Disconnect();
      
            bool success = await connectNewConnection();
            if (success)
                _connections[0].CurrentWorkingDirectoryChangedEvent += (s, e) =>
                    {
                        CurrentWorkingDirectory = e;
                    };
            return success;
        }

        public void Disconnect()
        {
            while (_connections.Count > 0)
            {
                _connections[0].Disconnect();
                _connections.RemoveAt(0);
            }
        }

        public bool Connected
        {
            get
            {
                if (_connections.Count > 0 && _connections[0] != null)
                    return _connections[0].LoggedIn;
                return false;

            }
        }

        #region FTP functions
        public async Task<List<IOElement>> ListFiles()
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return null;

            return await _connections[0].ListFiles();
        }

        public async Task<List<IOElement>> ListFiles(string absoluteDirectoryName)
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return null;

            return await _connections[0].ListFiles(absoluteDirectoryName);
        }

        public async void ChangeCurrentDirectory(string directory)
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return;

            _connections[0].ChangeWorkingDirectory(directory);
        }

        public async void GetSupportedCommands()
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return;

            _connections[0].GetSupportedCommands();
        }

        public async void BeginDownloadFile(string absoluteFileName, FileDownloadBytesReadDelegate bytesReadDelegate, FileDownloadFinished downloadFinished, IOTaskIsCanceledDelegate taskCanceled, bool binaryMode = false)
        {
            (await getIdledConnection()).BeginDownloadFile(absoluteFileName, bytesReadDelegate, downloadFinished, taskCanceled, binaryMode);
        }

        public async void BeginUploadFile(string absoluteFileName, FileUploadReadInputBytesDelegate readInputDelegate, FileUploadBytesWrittenDelegate bytesWrittenDelegate, FileUploadFinishedDelegate uploadFinishedDelegate, IOTaskIsCanceledDelegate taskCanceled, bool binaryMode = false)
        {
            await (await getIdledConnection()).BeginUploadFile(absoluteFileName, readInputDelegate, bytesWrittenDelegate, uploadFinishedDelegate, taskCanceled, binaryMode);
        }

        public async void CreateDirectory(string absoluteName)
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return;

            _connections[0].MakeDirectory(absoluteName);
        }

        public async void GetOS()
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return;

            _connections[0].GetOS();
        }

        public async Task<bool> DeleteDirectory(string absoluteDirectoryName)
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return false;

            return _connections[0].RemoveDirectory(absoluteDirectoryName);
        }

        public async Task<bool> DeleteFile(string absoluteFileName)
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return false;

            return _connections[0].DeleteFile(absoluteFileName);
        }

        public async Task<bool> RenameElement(string oldAbsoluteFileName, string newAbsoluteFileName)
        {
            if (_connections.Count == 0)
                if (!await connectNewConnection())
                    return false;

            return _connections[0].RenameFile(oldAbsoluteFileName, newAbsoluteFileName);
        }
        #endregion

        #region Helper Methods
        private async Task<FTPConnection> getIdledConnection()
        {
            for (int i = 1; i < _connections.Count; i++)
            {
                if (_connections[i].IsIdled)
                    return _connections[i];
            }

            await connectNewConnection();
            return _connections[_connections.Count - 1];
        }

        private async Task<bool> connectNewConnection()
        {
            var connection = new FTPConnection(Username, Password, new HostName(Server), Port.ToString(), this);
            connection.DisconnectedEvent += () =>
                {
                    _connections.Remove(connection);
                    connection = null;
                };
            connection.CommandSendEvent += (command) =>
                {
                    History += ("\nCLIENT:   " + command);
                };
            connection.AnswerReadEvent += (answer) =>
                {
                    History += ("\nSERVER:   " + answer);
                };

            connection.EncryptionMode = EncryptionMode;
            connection.ProtectionMode = ProtectionMode;
       

            //do this in the try block; maybe the connection cannot be established (e.g. IO problems)
            try
            {
                var isConnected = await connection.Connect();

                //now add the connection to the list because the connection was established at least once
                if (isConnected)
                {
                    _connections.Add(connection);
                }

                if (isConnected)
                {
                    return connection.Login();
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;
        }


        private bool _validateServerCertificate(X509CertificateStructure[] certificates)
        {
            if (_certificateAccepted)
                return true;

            switch (ValidationMode)
            {
                case SSLValidationMode.AcceptAll:
                    return true;
                case SSLValidationMode.AskForAll:
                    if (CertifacteValidationEvent != null)
                    {
                        bool res = CertifacteValidationEvent(certificates);
                        _certificateAccepted = res;
                        return res;
                    }
                    else
                        return false;
            }

            return true;
        }
        #endregion
    }
}
