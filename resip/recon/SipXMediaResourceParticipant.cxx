#include "SipXBridgeMixer.hxx"
#include "ReconSubsystem.hxx"
#include "SipXMediaResourceParticipant.hxx"
#include "SipXMediaStackAdapter.hxx"
#include "Conversation.hxx"
#include "UserAgent.hxx"

#include <rutil/Log.hxx>
#include <rutil/Logger.hxx>
#include <resip/stack/ExtensionParameter.hxx>
#include <rutil/WinLeakCheck.hxx>

#include "ConversationManagerCmds.hxx"
#include "SipXRemoteParticipant.hxx"

// sipX includes
#include <CpTopologyGraphInterface.h>
#include <mp/dtmflib.h>
#include <mp/MprFromFile.h>
// The ssrc_t typedef from MprEncode.h collides with one from libSrtp - we don't use it in this file, so just undefine it to avoid the compilation error
#undef ssrc_t  
#include <mp/MprEncode.h>
#include <mp/MpStreamPlayer.h>
#ifndef SIPX_NO_RECORD
#include <utl/CircularBufferPtr.h>
#endif

using namespace recon;
using namespace resip;
using namespace std;

#define RESIPROCATE_SUBSYSTEM ReconSubsystem::RECON

static const resip::ExtensionParameter p_participantonly("participant-only");
static const resip::ExtensionParameter p_append("append");
static const resip::ExtensionParameter p_silencetime("silencetime");  // in milliseconds
static const resip::ExtensionParameter p_format("format");
static const resip::ExtensionParameter p_numchannels("numchannels");


SipXMediaResourceParticipant::SipXMediaResourceParticipant(ParticipantHandle partHandle,
                                                   ConversationManager& conversationManager,
                                                   SipXMediaStackAdapter& sipXMediaStackAdapter,
                                                   const Uri& mediaUrl,
                                                   const std::shared_ptr<Data>& playAudioBuffer,
                                                   void* recordingCircularBuffer)
: Participant(partHandle, ConversationManager::ParticipantType_MediaResource, conversationManager),
  MediaResourceParticipant(partHandle, conversationManager, mediaUrl, playAudioBuffer),
  SipXParticipant(partHandle, ConversationManager::ParticipantType_MediaResource, conversationManager, sipXMediaStackAdapter),
  mStreamPlayer(0),
  mPortOnBridge(-1),
#ifndef SIPX_NO_RECORD
  mRecordingCircularBuffer((CircularBufferPtr*)recordingCircularBuffer)
#else
  mRecordingCircularBuffer(nullptr)
#endif
{
   InfoLog(<< "SipXMediaResourceParticipant created, handle=" << mHandle << " url=" << getMediaUrl());
#ifdef SIPX_NO_RECORD
   if(recordingCircularBuffer != 0)
   {
      ErrLog(<< "recordingCircularBuffer specified but recon is not compiled with support for CircularBuffer");
   }
#endif
}

SipXMediaResourceParticipant::~SipXMediaResourceParticipant()
{
   getMediaInterface()->unallocateResourceForMediaOperation(getResourceType(), mHandle);
      
   // Destroy stream player (if created)
   if(mStreamPlayer)
   {
      mStreamPlayer->removeListener(this);
      mStreamPlayer->destroy();
   }

   // Note:  Ideally this call would exist in the Participant Base class - but this call requires 
   //        dynamic_casts and virtual methods to function correctly during destruction.
   //        If the call is placed in the base Participant class then these things will not
   //        function as desired because a classes type changes as the descructors unwind.
   //        See https://stackoverflow.com/questions/10979250/usage-of-this-in-destructor.
   unregisterFromAllConversations();

   InfoLog(<< "SipXMediaResourceParticipant destroyed, handle=" << mHandle << " url=" << getMediaUrl());
}

void 
SipXMediaResourceParticipant::startResourceImpl()
{
   // Check if we have allocated a media resource yet or not
   if (mSipXResourceName.empty())
   {
      if (!getMediaInterface()->allocateAvailableResourceForMediaOperation(getResourceType(), mHandle, mSipXResourceName))
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource no available allocation for media participant of type=" << getResourceType());
         return;
      }
   }

   switch(getResourceType())
   {
   case Tone:
   {
      int toneid;
      bool isDtmf = false;
      if(getMediaUrl().host().size() == 1)
      {
         toneid = getMediaUrl().host().at(0);
         isDtmf = true;
      }
      else
      {
         if(isEqualNoCase(getMediaUrl().host(), dialtoneTone)) toneid = DTMF_TONE_DIALTONE;
         else if(isEqualNoCase(getMediaUrl().host(), busyTone)) toneid = DTMF_TONE_BUSY;
         else if(isEqualNoCase(getMediaUrl().host(), ringbackTone)) toneid = DTMF_TONE_RINGBACK;
         else if(isEqualNoCase(getMediaUrl().host(), ringTone)) toneid = DTMF_TONE_RINGTONE;
         else if(isEqualNoCase(getMediaUrl().host(), fastbusyTone)) toneid = DTMF_TONE_CALLFAILED;
         else if(isEqualNoCase(getMediaUrl().host(), backspaceTone)) toneid = DTMF_TONE_BACKSPACE;
         else if(isEqualNoCase(getMediaUrl().host(), callwaitingTone)) toneid = DTMF_TONE_CALLWAITING;
         else if(isEqualNoCase(getMediaUrl().host(), holdingTone)) toneid = DTMF_TONE_CALLHELD;
         else if(isEqualNoCase(getMediaUrl().host(), loudfastbusyTone)) toneid = DTMF_TONE_LOUD_FAST_BUSY;
         else
         {
            WarningLog(<< "SipXMediaResourceParticipant::startResource invalid tone identifier: " << getMediaUrl().host());
            return;
         }
      }

      OsStatus status = OS_FAILED;
      if(isDtmf && getMediaUrl().exists(p_participantonly))
      {
         ParticipantHandle partHandle = getMediaUrl().param(p_participantonly).convertUnsignedLong();
         SipXRemoteParticipant* participant = dynamic_cast<SipXRemoteParticipant*>(getConversationManager().getParticipant(partHandle));
         if(participant)
         {
            StackLog(<< "SipXMediaResourceParticipant::startResource: sending tone to sipX connection: " << participant->getMediaConnectionId());
#ifdef SIPX_NO_RECORD
            // Start RFC4733 out-of-band tone
            UtlString encodeName(DEFAULT_ENCODE_RESOURCE_NAME);
            MpResourceTopology::replaceNumInName(encodeName, participant->getMediaConnectionId());
            status = MprEncode::startTone(encodeName, *getMediaInterface()->getInterface()->getMsgQ(), toneid);
#else
            status = getMediaInterface()->getInterface()->startChannelOnlyTone(participant->getMediaConnectionId(), toneid);
#endif
            // We are NOT using the actual Tone resource from sipX when doing participant only, so we can free the allocation now, 
            // so that multiple participant only tone resources can be started.
            getMediaInterface()->unallocateResourceForMediaOperation(getResourceType(), mHandle);
         }
         else
         {
            WarningLog(<< "SipXMediaResourceParticipant::startResource Participant " << partHandle << " no longer exists or invalid");
         }
      }
      else
      {
#ifdef SIPX_NO_RECORD
         status = getMediaInterface()->getInterface()->startTone(toneid, TRUE /* local - unused */, TRUE /* remote - unused */);
#else
         // Note:  We are passing rfc4733Enabled as false, since sipX will send RFC4733 to all active RTP connections, and they may be in entirely different recon conversations
         status = getMediaInterface()->getInterface()->startTone(mSipXResourceName.c_str(), toneid, FALSE /* rfc4733Enabled? */);
#endif
      }
      if(status == OS_SUCCESS)
      {
         setRunning(true);
      }
      else
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource error calling startTone: " << status);
      }
   }
   break;

   case File:
   {
      Data filepath = getMediaUrl().host().urlDecoded();
      filepath.replace("|", ":");  // For Windows filepath processing - convert | to :

      InfoLog(<< "SipXMediaResourceParticipant playing, handle=" << mHandle << " filepath=" << filepath);

      SipXMediaInterface* mediaInterface = getMediaInterface().get();
#ifdef SIPX_NO_RECORD
      OsStatus status = mediaInterface->getInterface()->playAudio(filepath.c_str(),
         isRepeat() ? TRUE : FALSE /* repeast? */,
         TRUE /* local - unused */, TRUE /* remote - unused */);
#else
      OsStatus status = mediaInterface->getInterface()->playAudio(mSipXResourceName.c_str(), 
         filepath.c_str(), 
         isRepeat() ? TRUE : FALSE,
         TRUE /* autoStopAfterFinish? */,
         getStartOffsetMs());
#endif

      if(status == OS_SUCCESS)
      {
         setRunning(true);
      }
      else
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource error calling playAudio: " << status);
      }
   }
   break;

   case Cache:
   {
      Data cacheKey = getMediaUrl().host().urlDecoded();
      cacheKey.replace("|", ":");  // For Windows filepath processing - convert | to :

      InfoLog(<< "SipXMediaResourceParticipant playing, handle=" << mHandle << " cacheKey=" << cacheKey);

      Data* buffer;
      int type;
      if (getConversationManager().getBufferFromMediaResourceCache(cacheKey, &buffer, &type))
      {
         SipXMediaInterface* mediaInterface = getMediaInterface().get();
#ifdef SIPX_NO_RECORD
         OsStatus status = mediaInterface->getInterface()->playBuffer((char*)buffer->data(),
            buffer->size(),
            8000, /* rate */
            type,
            isRepeat() ? TRUE : FALSE /* repeat? */,
            TRUE /* local - unused */, TRUE /* remote - unused */);
#else
         OsStatus status = mediaInterface->getInterface()->playBuffer(mSipXResourceName.c_str(), 
            (char*)buffer->data(),
            (unsigned long)buffer->size(),
            8000, /* rate */
            type,
            isRepeat() ? TRUE : FALSE,
            NULL /* OsProtectedEvent */,
            TRUE /* autoStopAfterFinish? */,
            getStartOffsetMs());
#endif
         if (status == OS_SUCCESS)
         {
            setRunning(true);
         }
         else
         {
            WarningLog(<< "SipXMediaResourceParticipant::startResource error calling playAudio: " << status);
         }
      }
      else
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource media not found in cache, key: " << getMediaUrl().host());
      }
   }
   break;

   case Buffer:
   {
      Data audioBufferType = getMediaUrl().host();

      InfoLog(<< "SipXMediaResourceParticipant playing, handle=" << mHandle << " audioBufferType=" << audioBufferType);

      if (resip::isEqualNoCase("RAW_PCM_16", audioBufferType))
      {
         Data* buffer = getAudioBuffer().get();

         if (buffer && buffer->size() > 0)
         {
            SipXMediaInterface* mediaInterface = getMediaInterface().get();
#ifdef SIPX_NO_RECORD
            OsStatus status = mediaInterface->getInterface()->playBuffer((char*)buffer->data(),
               buffer->size(),
               8000, /* rate */
               0,  // RAW_PCM_16 = 0 - always correct for SipXMedia:  see sipXTapi.h: SIPX_AUDIO_DATA_FORMAT
               isRepeat() ? TRUE : FALSE /* repeat? */,
               TRUE /* local - unused */, TRUE /* remote - unused */);
#else
            OsStatus status = mediaInterface->getInterface()->playBuffer(mSipXResourceName.c_str(),
               (char*)buffer->data(),
               (unsigned long)buffer->size(),
               8000, /* rate */
               0,  // RAW_PCM_16 = 0 - always correct for SipXMedia:  see sipXTapi.h: SIPX_AUDIO_DATA_FORMAT
               isRepeat() ? TRUE : FALSE,
               NULL /* OsProtectedEvent */,
               TRUE /* autoStopAfterFinish? */,
               getStartOffsetMs());
#endif
            if (status == OS_SUCCESS)
            {
               setRunning(true);
            }
            else
            {
               WarningLog(<< "SipXMediaResourceParticipant::startResource error calling playAudio: " << status);
            }
         }
         else
         {
            WarningLog(<< "SipXMediaResourceParticipant::startResource buffer type, but no audio buffer was provided.");
         }
      }
      else
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource buffer type is not recognized: " << audioBufferType);
      }
   }
   break;
 
   // Warning: The stream player has been deprecated from the SipX CpTopologyGraphInterface - leaving code in place in case it ever get's
   //          re-implemented.  If someone tries to play from Http or Https with sipX it will fail at the createPlayer call below, and
   //          the MediaResourceParticipant will self destruct.
   case Http:
   case Https:
   {
      int flags = STREAM_SOUND_LOCAL | STREAM_SOUND_REMOTE;

      OsStatus status = getMediaInterface()->getInterface()->createPlayer(&mStreamPlayer, Data::from(getMediaUrl()).c_str(), flags);
      if(status == OS_SUCCESS)
      {
         mStreamPlayer->addListener(this);
         status = mStreamPlayer->realize(FALSE /* block? */);
         if(status != OS_SUCCESS)
         {
            WarningLog(<< "SipXMediaResourceParticipant::startResource error calling StreamPlayer::realize: " << status);
         }
         else
         {
            setRunning(true);
         }
      }
      else
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource error calling createPlayer: " << status);
      }
   }
   break;

   case Record:
   case RecordMultiChannel:
   {
#ifdef SIPX_NO_RECORD
      ErrLog(<< "support for Record was not enabled at compile time");
#else
      int silenceTimeMs = -1;  // disabled
      if (getMediaUrl().exists(p_silencetime))
      {
         silenceTimeMs = getMediaUrl().param(p_silencetime).convertInt();
      }

      int numChannels = 1;
      if (getResourceType() == RecordMultiChannel && getMediaUrl().exists(p_numchannels))
      {
         numChannels = getMediaUrl().param(p_numchannels).convertInt();
         if (numChannels < 1)
         {
            numChannels = 1;
         } 
         else if (numChannels > 2)
         {
            numChannels = 2;
         }
      }

      CpMediaInterface::CpAudioFileFormat format = CpMediaInterface::CP_WAVE_PCM_16;  // Default recording format
      Data formatString(recordingFormatWAVPCM16);
      if (getMediaUrl().exists(p_format))
      {
         Data& urlFormatString = getMediaUrl().param(p_format);
         if (isEqualNoCase(urlFormatString, recordingFormatWAVMULAW))
         {
            format = CpMediaInterface::CP_WAVE_MULAW;
            formatString = recordingFormatWAVMULAW;
         }
         else if (isEqualNoCase(urlFormatString, recordingFormatWAVALAW))
         {
            format = CpMediaInterface::CP_WAVE_ALAW;
            formatString = recordingFormatWAVALAW;
         }
         else if (isEqualNoCase(urlFormatString, recordingFormatWAVGSM))
         {
            format = CpMediaInterface::CP_WAVE_GSM;
            formatString = recordingFormatWAVGSM;
         }
         else if (isEqualNoCase(urlFormatString, recordingFormatOGGOPUS))
         {
            format = CpMediaInterface::CP_OGG_OPUS;
            formatString = recordingFormatOGGOPUS;
         }
      }

      SipXMediaInterface* mediaInterface = getMediaInterface().get();

      // If recording to circular buffer, then do that now, and return
      if (isEqualNoCase(getMediaUrl().host(), "circularbuffer") && mRecordingCircularBuffer)
      {
         // Set Watermark level at 5/6 of the circular buffer size
         unsigned long recordingBufferNotificationWatermark = mRecordingCircularBuffer->getCapacity() / 5 * 4;

         InfoLog(<< "SipXMediaResourceParticipant recording to CircularBuffer, handle=" << mHandle << ", format=" << formatString << ", maxDurationMs=" << getDurationMs() << ", silenceTimeMs=" << silenceTimeMs << ", circularBufferCapacity=" << mRecordingCircularBuffer->getCapacity() << ", recordingBufferNotificationWatermark=" << recordingBufferNotificationWatermark);

         // We are passing the CircularBufferPtr to sipX - it will call release when it's done with the buffer - add it's reference now
         mRecordingCircularBuffer->addRef();

         OsStatus status = mediaInterface->getInterface()->recordCircularBufferAudio(
            mSipXResourceName.c_str(),
            *mRecordingCircularBuffer,
            format,
            recordingBufferNotificationWatermark,
            getDurationMs() /* maxTime Ms */,
            silenceTimeMs /* silenceLength Ms, -1 to disable */,
            numChannels,
            FALSE /* setupMultiChannelMixesAutomatically? */);

         if (status == OS_SUCCESS)
         {
            mRecordingCircularBuffer = 0;  // The application and sipX control the lifetime of the CircularBuffer, clear out our pointer, so we are not tempted to use it.
            setRunning(true);
         }
         else
         {
            mRecordingCircularBuffer->release();  // Failed to handoff ownership to sipX, release the reference we added above
            mRecordingCircularBuffer = 0;
            WarningLog(<< "SipXMediaResourceParticipant::startResource error calling recordCircularBufferAudio: " << status);
         }

         return;
      }

      Data filepath = getMediaUrl().host().urlDecoded();
      filepath.replace("|", ":");  // For Windows filepath processing - convert | to :

      bool append = getMediaUrl().exists(p_append);

      InfoLog(<< "SipXMediaResourceParticipant recording, handle=" << mHandle << " filepath=" << filepath << ", format=" << formatString << ", append=" << (append ? "YES" : "NO") << ", maxDurationMs=" << getDurationMs() << ", silenceTimeMs=" << silenceTimeMs);

      // Note:  If mediaStackAdapter.extraPlayAndRecordResourcesEnabled is disabled then there is a single multi-channel
      //        recording resource.  If enabled, then there are two recording resources, one multichannel
      //        resources and one single channel recording resource.  The numChannels parameter is only processed
      //        for the multichannel recording resource.  Media URL scheme of "record-mc" is for the multichannel resource
      //        and "record" specifies to use the single channel recorder.  
      // 
      //        For the multichannel resource (with numChannels set to 2 on the record operation; all participants are by 
      //        default mixed to the left channel.  Any participant with RecordChannelNum set to 2 will be mixed to
      //        the right channel.
      //        
      // Caveats: 
      //        1. There are bugs in sipX with multi-channel GSM WAV recording.
      //        2. There are bugs in sipX with multi-channel OPUS OGG recording.
      //        3. Automatic trimming of silence is not supported for OPUS recordings.
      OsStatus status = mediaInterface->getInterface()->recordAudio(
         mSipXResourceName.c_str(),
         filepath.c_str(),
         format,
         append /* append? */,
         numChannels /* numChannels */,
         getDurationMs() /* maxTime Ms */,
         silenceTimeMs /* silenceLength Ms, -1 to disable */,
         FALSE /* setupMixesAutomatically? */);
      if (status == OS_SUCCESS)
      {
         setRunning(true);
      }
      else
      {
         WarningLog(<< "SipXMediaResourceParticipant::startResource error calling recordAudio: " << status);
      }
#endif
   }
   break;

   case Invalid:
      WarningLog(<< "SipXMediaResourceParticipant::startResource invalid resource type: " << getMediaUrl().scheme());
      break;
   
   default:
      resip_assert(false);
   }
}

bool
SipXMediaResourceParticipant::stopResource()
{
   bool okToDeleteNow = true;

   if (isRunning())
   {
      switch (getResourceType())
      {
      case Tone:
      {
         OsStatus status = OS_FAILED;
         bool isDtmf = (getMediaUrl().host().size() == 1);
         if (isDtmf && getMediaUrl().exists(p_participantonly))
         {
            int partHandle = getMediaUrl().param(p_participantonly).convertInt();
            SipXRemoteParticipant* participant = dynamic_cast<SipXRemoteParticipant*>(getConversationManager().getParticipant(partHandle));
            if (participant)
            {
#ifdef SIPX_NO_RECORD
               // Stop RFC4733 out-of-band tone
               UtlString encodeName(DEFAULT_ENCODE_RESOURCE_NAME);
               MpResourceTopology::replaceNumInName(encodeName, participant->getMediaConnectionId());
               status = MprEncode::stopTone(encodeName, *getMediaInterface()->getInterface()->getMsgQ());
#else
               status = getMediaInterface()->getInterface()->stopChannelOnlyTone(participant->getMediaConnectionId());
#endif
            }
            else
            {
               WarningLog(<< "SipXMediaResourceParticipant::stopResource participant " << partHandle << " no longer exists or invalid");
            }
         }
         else
         {
#ifdef SIPX_NO_RECORD
            status = getMediaInterface()->getInterface()->stopTone();
#else
            status = getMediaInterface()->getInterface()->stopTone(mSipXResourceName.c_str(), FALSE);
#endif
         }
         if (status != OS_SUCCESS)
         {
            WarningLog(<< "SipXMediaResourceParticipant::stopResource error calling stopTone: " << status);
         }
      }
      break;
      case File:
      case Cache:
      case Buffer:
      {
#ifdef SIPX_NO_RECORD
         OsStatus status = getMediaInterface()->getInterface()->stopAudio();
#else
         resip_assert(!mSipXResourceName.empty());
         OsStatus status = getMediaInterface()->getInterface()->stopAudio(mSipXResourceName.c_str());
#endif
         if (status != OS_SUCCESS)
         {
            WarningLog(<< "SipXMediaResourceParticipant::stopResource error calling stopAudio: " << status);
         }
      }
      break;
      case Http:
      case Https:
      {
         setRepeat(false);  // Required so that player will not just repeat on stopped event
         OsStatus status = mStreamPlayer->stop();
         if (status != OS_SUCCESS)
         {
            WarningLog(<< "SipXMediaResourceParticipant::stopResource error calling StreamPlayer::stop: " << status);
         }
         else
         {
            okToDeleteNow = false;  // Wait for play finished event to come in
         }
      }
      break;
      case Record:
      case RecordMultiChannel:
      {
#ifndef SIPX_NO_RECORD
         OsStatus status = getMediaInterface()->getInterface()->stopRecordAudio(mSipXResourceName.c_str());
         if (status != OS_SUCCESS)
         {
            WarningLog(<< "SipXMediaResourceParticipant::stopResource error calling stopRecordAudio: " << status);
         }
#endif
      }
      break;
      case Invalid:
         WarningLog(<< "SipXMediaResourceParticipant::stopResource invalid resource type: " << getResourceType());
         break;
      default:
         resip_assert(false);
      }
   }
   return okToDeleteNow;
}

int 
SipXMediaResourceParticipant::getConnectionPortOnBridge()
{
   if (mPortOnBridge == -1)
   {
      resip_assert(getMediaInterface() != 0);

      // Check if we have allocated a media resource yet or not
      if (mSipXResourceName.empty())
      {
         if (!getMediaInterface()->allocateAvailableResourceForMediaOperation(getResourceType(), mHandle, mSipXResourceName))
         {
            WarningLog(<< "SipXMediaResourceParticipant::getConnectionPortOnBridge no available allocation for media participant of type=" << getResourceType());
            return -1;
         }
      }
      if (getResourceType() == Record ||
          getResourceType() == RecordMultiChannel)
      {
#ifdef SIPX_NO_RECORD
         ErrLog(<< "support for Record was not enabled at compile time");
#else
         getMediaInterface()->getInterface()->getResourceOutputPortOnBridge(mSipXResourceName.c_str(), 0, mPortOnBridge);
#endif
      }
      else
      { 
         getMediaInterface()->getInterface()->getResourceInputPortOnBridge(mSipXResourceName.c_str(), 0, mPortOnBridge);
      }
      InfoLog(<< "SipXMediaResourceParticipant getConnectionPortOnBridge, handle=" << mHandle << ", mPortOnBridge=" << mPortOnBridge);
   }
   resip_assert(mPortOnBridge != -1);
   return mPortOnBridge;
}

void 
SipXMediaResourceParticipant::playerRealized(MpPlayerEvent& event)
{
   InfoLog(<< "SipXMediaResourceParticipant::playerRealized: handle=" << mHandle);
   if(isPrefetch())
   {
      OsStatus status = mStreamPlayer->prefetch(FALSE);
      if(status != OS_SUCCESS)
      {
         WarningLog(<< "SipXMediaResourceParticipant::playerRealized error calling StreamPlayer::prefetch: " << status);
         MediaResourceParticipantDeleterCmd* cmd = new MediaResourceParticipantDeleterCmd(getConversationManager(), mHandle);
         getConversationManager().post(cmd);
      }
   }
   else
   {
      OsStatus status = mStreamPlayer->play(FALSE /*block?*/);
      if(status != OS_SUCCESS)
      {
         WarningLog(<< "SipXMediaResourceParticipant::playerRealized error calling StreamPlayer::play: " << status);
         MediaResourceParticipantDeleterCmd* cmd = new MediaResourceParticipantDeleterCmd(getConversationManager(), mHandle);
         getConversationManager().post(cmd);
      }
   }
}

void 
SipXMediaResourceParticipant::playerPrefetched(MpPlayerEvent& event)
{
   InfoLog(<< "SipXMediaResourceParticipant::playerPrefetched: handle=" << mHandle);
   OsStatus status = mStreamPlayer->play(FALSE/*block?*/);
   if(status != OS_SUCCESS)
   {
      WarningLog(<< "SipXMediaResourceParticipant::playerPrefetched error calling StreamPlayer::play: " << status);
       MediaResourceParticipantDeleterCmd* cmd = new MediaResourceParticipantDeleterCmd(getConversationManager(), mHandle);
       getConversationManager().post(cmd);
   }
}

void 
SipXMediaResourceParticipant::playerPlaying(MpPlayerEvent& event)
{
   InfoLog(<< "SipXMediaResourceParticipant::playerPlaying: handle=" << mHandle);
}

void 
SipXMediaResourceParticipant::playerPaused(MpPlayerEvent& event)
{
   InfoLog(<< "SipXMediaResourceParticipant::playerPaused: handle=" << mHandle);
}

void 
SipXMediaResourceParticipant::playerStopped(MpPlayerEvent& event)
{
   InfoLog(<< "SipXMediaResourceParticipant::playerStopped: handle=" << mHandle);
   // We get this event when playing is completed
   if(isRepeat())
   {
      OsStatus status = mStreamPlayer->rewind(FALSE/*block?*/);   // Generate playerPrefetched event
      if(status != OS_SUCCESS)
      {
         WarningLog(<< "SipXMediaResourceParticipant::playerStopped error calling StreamPlayer::rewind: " << status);
         MediaResourceParticipantDeleterCmd* cmd = new MediaResourceParticipantDeleterCmd(getConversationManager(), mHandle);
         getConversationManager().post(cmd);
      }
   }
   else
   {
      MediaResourceParticipantDeleterCmd* cmd = new MediaResourceParticipantDeleterCmd(getConversationManager(), mHandle);
      getConversationManager().post(cmd);
   }
}
 
void 
SipXMediaResourceParticipant::playerFailed(MpPlayerEvent& event)
{
   InfoLog(<< "SipXMediaResourceParticipant::playerFailed: handle=" << mHandle);
   MediaResourceParticipantDeleterCmd* cmd = new MediaResourceParticipantDeleterCmd(getConversationManager(), mHandle);
   getConversationManager().post(cmd);
}


/* ====================================================================

 Copyright (c) 2021-2023, SIP Spectrum, Inc. http://www.sipspectrum.com
 Copyright (c) 2021, Daniel Pocock https://danielpocock.com
 Copyright (c) 2007-2008, Plantronics, Inc.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are 
 met:

 1. Redistributions of source code must retain the above copyright 
    notice, this list of conditions and the following disclaimer. 

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution. 

 3. Neither the name of Plantronics nor the names of its contributors 
    may be used to endorse or promote products derived from this 
    software without specific prior written permission. 

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ==================================================================== */
