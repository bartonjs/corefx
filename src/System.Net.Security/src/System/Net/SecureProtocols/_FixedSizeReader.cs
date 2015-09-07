// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;

namespace System.Net
{
    //
    // Reads a fixed size packet from a stream, can disover EOF as 0 bytes read from stream.
    //
    internal class FixedSizeReader
    {
        private static readonly AsyncCallback s_readCallback = new AsyncCallback(ReadCallback);

        // TODO: Implement this using TPL instead of APM.
        private readonly StreamAsyncHelper _TransportAPM;
        private readonly Stream _Transport;
        private AsyncProtocolRequest _Request;
        private int _TotalRead;

        public FixedSizeReader(Stream transport)
        {
            _Transport = transport;
            _TransportAPM = new StreamAsyncHelper(transport);
        }

        //
        // Returns 0 on legitimate EOF or if 0 bytes was requested, otheriwse reads as directed or throws.
        // Returns count on success.
        //
        public int ReadPacket(byte[] buffer, int offset, int count)
        {
            int tempCount = count;
            do
            {
                int bytes = _Transport.Read(buffer, offset, tempCount);

                if (bytes == 0)
                {
                    if (tempCount != count)
                    {
                        throw new IOException(SR.net_io_eof);
                    }
                    return 0;
                }

                tempCount -= bytes;
                offset += bytes;
            } while (tempCount != 0);

            return count;
        }

        //
        // Completes "_Request" with 0 if 0 bytes was requested or legitimate EOF received.
        // Otheriwse, reads as directed or completes "_Request" with an Exception or throws.
        //
        public void AsyncReadPacket(AsyncProtocolRequest request)
        {
            _Request = request;
            _TotalRead = 0;
            StartReading();
        }
        //
        // Loops while subsequest completions are sync.
        //
        private void StartReading()
        {
            while (true)
            {
                IAsyncResult ar = _TransportAPM.BeginRead(_Request.Buffer, _Request.Offset + _TotalRead, _Request.Count - _TotalRead, s_readCallback, this);
                if (!ar.CompletedSynchronously)
                {
#if DEBUG
                    _Request._DebugAsyncChain = ar;
#endif
                    break;
                }

                int bytes = _TransportAPM.EndRead(ar);

                if (CheckCompletionBeforeNextRead(bytes))
                {
                    break;
                }
            }
        }

        private bool CheckCompletionBeforeNextRead(int bytes)
        {
            if (bytes == 0)
            {
                // 0 bytes was requested or EOF in the beginning of a frame, the caller should decide whether it's OK.
                if (_TotalRead == 0)
                {
                    _Request.CompleteRequest(0);
                    return true;
                }

                // EOF in the middle of a frame.
                throw new IOException(SR.net_io_eof);
            }

            GlobalLog.Assert(_TotalRead + bytes <= _Request.Count, "FixedSizeReader::CheckCompletion()|State got out of range. Total:{0} Count:{1}", _TotalRead + bytes, _Request.Count);

            if ((_TotalRead += bytes) == _Request.Count)
            {
                _Request.CompleteRequest(_Request.Count);
                return true;
            }
            return false;
        }

        private static void ReadCallback(IAsyncResult transportResult)
        {
            GlobalLog.Assert(transportResult.AsyncState is FixedSizeReader, "ReadCallback|State type is wrong, expected FixedSizeReader.");
            if (transportResult.CompletedSynchronously)
            {
                return;
            }

            FixedSizeReader reader = (FixedSizeReader)transportResult.AsyncState;
            AsyncProtocolRequest request = reader._Request;

            // Async completion.
            try
            {
                int bytes = reader._TransportAPM.EndRead(transportResult);

                if (reader.CheckCompletionBeforeNextRead(bytes))
                {
                    return;
                }
                reader.StartReading();
            }
            catch (Exception e)
            {
                if (request.IsUserCompleted)
                    throw;
                request.CompleteWithError(e);
            }
        }
    }
}
