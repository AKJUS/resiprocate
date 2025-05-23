#if !defined(RESIP_DIALOGUSAGEMANAGER_HXX)
#define RESIP_DIALOGUSAGEMANAGER_HXX

#include <vector>
#include <set>
#include <map>
#include <utility>

#include "resip/stack/Headers.hxx"
#include "resip/dum/EventDispatcher.hxx"
#include "resip/dum/DialogEventInfo.hxx"
#include "resip/dum/DialogSet.hxx"
#include "resip/dum/DumTimeout.hxx"
#include "resip/dum/HandleManager.hxx"
#include "resip/dum/Handles.hxx"
#include "resip/dum/MergedRequestKey.hxx"
#include "resip/dum/RegistrationPersistenceManager.hxx"
#include "resip/dum/PublicationPersistenceManager.hxx"
#include "resip/dum/ServerSubscription.hxx"
#include "rutil/BaseException.hxx"
#include "rutil/ThreadIf.hxx"
#include "resip/stack/SipStack.hxx"
#include "resip/stack/TransactionUser.hxx"
#include "resip/dum/DumFeature.hxx"
#include "resip/dum/DumFeatureChain.hxx"
#include "resip/dum/DumFeatureMessage.hxx"
#include "resip/dum/TargetCommand.hxx"
#include "resip/dum/ClientSubscriptionFunctor.hxx"
#include "resip/dum/ServerSubscriptionFunctor.hxx"

#include <memory>

namespace resip 
{

class Security;
class SipStack;
class FdSet;
class MasterProfile;
class RedirectManager;
class ClientAuthManager;
class ServerAuthManager;
class Uri;
class Contents;

class ClientRegistrationHandler;
class ServerRegistrationHandler;
class InviteSessionHandler;
class ClientSubscriptionHandler;
class ServerSubscriptionHandler;
class ClientPublicationHandler;
class ServerPublicationHandler;
class ClientPagerMessageHandler;
class ServerPagerMessageHandler;
class OutOfDialogHandler;
class RedirectHandler;
class DialogSetHandler;
class RequestValidationHandler;

class Dialog;
class InviteSessionCreator;

class AppDialogSetFactory;
class DumShutdownHandler;
class RemoteCertStore;

class KeepAliveManager;
class HttpGetMessage;

class ConnectionTerminated;

class ExternalMessageBase;
class ExternalMessageHandler;

class DialogEventStateManager;
class DialogEventHandler;

class DialogUsageManager : public HandleManager, public TransactionUser
{
   public:
      class Exception final : public BaseException
      {
         public:
            Exception(const Data& msg,
                      const Data& file,
                      const int line)
               : BaseException(msg, file, line)
            {}
            
            const char* name() const noexcept override { return "DialogUsageManager::Exception"; }
      };

      typedef enum
      {
         None = 0,
         Sign,
         Encrypt,
         SignAndEncrypt
      } EncryptionLevel;
  
      // If createDefaultFeatures is true dum will construct a
      // IdentityHandler->EncryptionManager chain.
      DialogUsageManager(SipStack& stack, bool createDefaultFeatures=false);
      virtual ~DialogUsageManager();
      
      // !bwc! Maybe add a giveUpSeconds param to these.
      void shutdown(DumShutdownHandler*);

      // !bwc! This is not properly implemented (has an assert(0) in it). 
      // I am removing this declaration.
      // void shutdownIfNoUsages(DumShutdownHandler*);

      void forceShutdown(DumShutdownHandler*);

      // Use SipStack::addTransport instead
      RESIP_DEPRECATED(void addTransport( TransportType protocol,
                         int port=0, 
                         IpVersion version=V4,
                         const Data& ipInterface = Data::Empty, 
                         const Data& sipDomainname = Data::Empty, // only used
                                                                  // for TLS
                                                                  // based stuff 
                         const Data& privateKeyPassPhrase = Data::Empty,
                         SecurityTypes::SSLType sslType = SecurityTypes::SSLv23,
                         unsigned transportFlags = 0));

      SipStack& getSipStack();
      const SipStack& getSipStack() const;
      Security* getSecurity();
      
      Data getHostAddress();

      void setAppDialogSetFactory(std::unique_ptr<AppDialogSetFactory>) noexcept;

      void setMasterProfile(const std::shared_ptr<MasterProfile>& masterProfile);
      std::shared_ptr<MasterProfile>& getMasterProfile();
      std::shared_ptr<UserProfile>& getMasterUserProfile();
      
      //optional handler to track the progress of DialogSets
      void setDialogSetHandler(DialogSetHandler* handler) noexcept;

      void setKeepAliveManager(std::unique_ptr<KeepAliveManager> keepAlive) noexcept;

      //There is a default RedirectManager.  Setting one may cause the old one
      //to be deleted. 
      void setRedirectManager(std::unique_ptr<RedirectManager> redirect) noexcept;
      //informational, so a RedirectHandler is not required
      void setRedirectHandler(RedirectHandler* handler) noexcept;
      RedirectHandler* getRedirectHandler() const noexcept;

      /// If there is no ClientAuthManager, when the client receives a 401/407,
      /// pass it up through the normal BaseUsageHandler
      void setClientAuthManager(std::unique_ptr<ClientAuthManager> client) noexcept;

      /// If there is no ServerAuthManager, the server does not authenticate requests
      void setServerAuthManager(std::shared_ptr<ServerAuthManager> server);

      /// If there is no such handler, calling makeInviteSession will throw and
      /// receiving an INVITE as a UAS will respond with 405 Method Not Allowed.
      void setInviteSessionHandler(InviteSessionHandler*);
      
      /// If there is no such handler, calling makeRegistration will throw
      void setClientRegistrationHandler(ClientRegistrationHandler*);

      /// If no such handler, UAS will respond to REGISTER with 405 Method Not Allowed
      void setServerRegistrationHandler(ServerRegistrationHandler*);

      /// If there is no such handler, calling makeSubscription will throw
      void addClientSubscriptionHandler(const Data& eventType, ClientSubscriptionHandler*);

      /// If there is no such handler, calling makePublication will throw
      void addClientPublicationHandler(const Data& eventType, ClientPublicationHandler*);
      
      void addServerSubscriptionHandler(const Data& eventType, ServerSubscriptionHandler*);
      void addServerPublicationHandler(const Data& eventType, ServerPublicationHandler*);
      
      void addOutOfDialogHandler(MethodTypes, OutOfDialogHandler*);

      void setRequestValidationHandler(RequestValidationHandler*);

      void setClientPagerMessageHandler(ClientPagerMessageHandler*) noexcept;
      void setServerPagerMessageHandler(ServerPagerMessageHandler*) noexcept;

      /// Add/Remove External Message Handler
      /// do following op when processing thread in not running
      void addExternalMessageHandler(ExternalMessageHandler* handler);
      void removeExternalMessageHandler(ExternalMessageHandler* handler);
      void clearExternalMessageHandler();

      /// Sets a manager to handle storage of registration or publication state
      void setRegistrationPersistenceManager(RegistrationPersistenceManager*);
      RegistrationPersistenceManager* getRegistrationPersistenceManager() { return mRegistrationPersistenceManager; }
      void setPublicationPersistenceManager(PublicationPersistenceManager*);
      PublicationPersistenceManager* getPublicationPersistenceManager() { return mPublicationPersistenceManager; }
      
      // The message is owned by the underlying datastructure and may go away in
      // the future. If the caller wants to keep it, it should make a copy. The
      // memory will exist at least up until the point where the application
      // calls DialogUsageManager::send(msg);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, const Contents* initialOffer, AppDialogSet* ads = nullptr);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, const Contents* initialOffer, AppDialogSet* ads = nullptr);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, const Contents* initialOffer, EncryptionLevel level, const Contents* alternative = nullptr, AppDialogSet* ads = nullptr);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, const Contents* initialOffer, EncryptionLevel level, const Contents* alternative = nullptr, AppDialogSet* ads = nullptr);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, const DialogSetId& dialogSetId, const std::shared_ptr<UserProfile>& userProfile, const Contents* initialOffer, EncryptionLevel level, const Contents* alternative = nullptr, AppDialogSet* ads = nullptr);
      // Versions that add a replaces header
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, InviteSessionHandle sessionToReplace, const std::shared_ptr<UserProfile>& userProfile, const Contents* initialOffer, AppDialogSet* ads = nullptr);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, InviteSessionHandle sessionToReplace, const std::shared_ptr<UserProfile>& userProfile, const Contents* initialOffer, EncryptionLevel level = None, const Contents* alternative = nullptr, AppDialogSet* ads = nullptr);
      std::shared_ptr<SipMessage> makeInviteSession(const NameAddr& target, InviteSessionHandle sessionToReplace, const Contents* initialOffer, EncryptionLevel level = None, const Contents* alternative = nullptr, AppDialogSet* ads = nullptr);
      
      //will send a Notify(100)...currently can be decorated through the
      //OnReadyToSend callback.  Probably will change it's own callback/handler soon
      std::shared_ptr<SipMessage> makeInviteSessionFromRefer(const SipMessage& refer, ServerSubscriptionHandle,
                                                       const Contents* initialOffer, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeInviteSessionFromRefer(const SipMessage& refer, const std::shared_ptr<UserProfile>& userProfile,
                                                       const Contents* initialOffer, AppDialogSet* appDs = nullptr);
      std::shared_ptr<SipMessage> makeInviteSessionFromRefer(const SipMessage& refer, ServerSubscriptionHandle,
                                                       const Contents* initialOffer, EncryptionLevel level = None, const Contents* alternative = nullptr, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeInviteSessionFromRefer(const SipMessage& refer, const std::shared_ptr<UserProfile>& userProfile, ServerSubscriptionHandle,
                                                       const Contents* initialOffer, EncryptionLevel level = None, const Contents* alternative = nullptr, AppDialogSet* = nullptr);
      
      std::shared_ptr<SipMessage> makeSubscription(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, const Data& eventType, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeSubscription(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, const Data& eventType,
                                             uint32_t subscriptionTime, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeSubscription(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, const Data& eventType,
                                             uint32_t subscriptionTime, int refreshInterval, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeSubscription(const NameAddr& target, const Data& eventType, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeSubscription(const NameAddr& target, const Data& eventType, uint32_t subscriptionTime, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeSubscription(const NameAddr& target, const Data& eventType,
                                             uint32_t subscriptionTime, int refreshInterval, AppDialogSet* = nullptr);

      //unsolicited refer
      std::shared_ptr<SipMessage> makeRefer(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, const H_ReferTo::Type& referTo, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeRefer(const NameAddr& target, const H_ReferTo::Type& referTo, AppDialogSet* = nullptr);

      std::shared_ptr<SipMessage> makePublication(const NameAddr& target,
                                            const std::shared_ptr<UserProfile>& userProfile,
                                            const Contents& body, 
                                            const Data& eventType, 
                                            uint32_t expiresSeconds, 
                                            AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makePublication(const NameAddr& target,
                                            const Contents& body, 
                                            const Data& eventType, 
                                            uint32_t expiresSeconds, 
                                            AppDialogSet* = nullptr);

      std::shared_ptr<SipMessage> makeRegistration(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeRegistration(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, uint32_t registrationTime, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeRegistration(const NameAddr& target, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeRegistration(const NameAddr& target, uint32_t registrationTime, AppDialogSet* = nullptr);

      std::shared_ptr<SipMessage> makeOutOfDialogRequest(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, MethodTypes meth, AppDialogSet* = nullptr);
      std::shared_ptr<SipMessage> makeOutOfDialogRequest(const NameAddr& target, MethodTypes meth, AppDialogSet* = nullptr);

      ClientPagerMessageHandle makePagerMessage(const NameAddr& target, const std::shared_ptr<UserProfile>& userProfile, AppDialogSet* = nullptr);
      ClientPagerMessageHandle makePagerMessage(const NameAddr& target, AppDialogSet* = nullptr);
      
      void end(DialogSetId invSessionId);
      void send(std::shared_ptr<SipMessage> request);
      void sendCommand(std::shared_ptr<SipMessage> request);

      class SendCommand : public DumCommandAdapter
      {
         public:
            SendCommand(std::shared_ptr<SipMessage> request,
                        DialogUsageManager& dum):
               mRequest(request),
               mDum(dum)
            {
            }

            void executeCommand() override
            {
               mDum.send(mRequest);
            }

            EncodeStream& encodeBrief(EncodeStream& strm) const override
            {
               return strm << "DialogUsageManager::SendCommand" << std::endl;
            }

         protected:
            std::shared_ptr<SipMessage> mRequest;
            DialogUsageManager& mDum;
      };

      //void send(SipMessage& request, EncryptionLevel level);
      
      // give dum an opportunity to handle its events. If process() returns true
      // there are more events to process.
      bool hasEvents() const;

      // process methods that take an optional lock when processing occurs
      bool process(Mutex* mutex = NULL);  // non-blocking
      bool process(int timeoutMs, Mutex* mutex = NULL);   // Specify -1 for infinte timeout

      // process methods that take a recursive lock when processing occurs
      bool process(RecursiveMutex& mutex);  // non-blocking
      bool process(int timeoutMs, RecursiveMutex& mutex);   // Specify -1 for infinte timeout

      AppDialogHandle findAppDialog(const DialogId& id);
      AppDialogSetHandle findAppDialogSet(const DialogSetId& id);

      InviteSessionHandle findInviteSession(const DialogId& id);
      //if the handle is inValid, int represents the errorcode
      std::pair<InviteSessionHandle, int> findInviteSession(const CallId& replaces);

      ClientPublicationHandler* getClientPublicationHandler(const Data& eventType);
      ServerPublicationHandler* getServerPublicationHandler(const Data& eventType);

      ClientSubscriptionHandler* getClientSubscriptionHandler(const Data& eventType);
      ServerSubscriptionHandler* getServerSubscriptionHandler(const Data& eventType);

      // will apply the specified functor(which takes a
      //ServerSubscriptionHandle) to each matching ServerSubscription.  
      //Returns the functor after the last application.
      template<typename UnaryFunction>
      UnaryFunction applyToServerSubscriptions(const Data& aor, 
                                               const Data& eventType, 
                                               UnaryFunction& applyFn)
      {
         Data key = eventType + aor;
         std::pair<ServerSubscriptions::iterator,ServerSubscriptions::iterator> 
            range = mServerSubscriptions.equal_range(key);
         
         for (ServerSubscriptions::iterator i=range.first; i!=range.second; ++i)
         {
            ServerSubscriptionHandle h = i->second->getHandle();
            applyFn(h);
         }
         return applyFn;
      }

      //DUM will delete features in its destructor. Feature manipulation should
      //be done before any processing starts.
      //ServerAuthManager is now a DumFeature; setServerAuthManager is a special
      //case of addFeature; the ServerAuthManager should always be the first
      //feature in the chain.
      void addIncomingFeature(std::shared_ptr<DumFeature> feat);
      void addOutgoingFeature(std::shared_ptr<DumFeature> feat);

      void setOutgoingMessageInterceptor(std::shared_ptr<DumFeature> feat) noexcept;

      TargetCommand::Target& dumIncomingTarget();

      TargetCommand::Target& dumOutgoingTarget();

      //exposed so DumThread variants can be written
      Message* getNext(int ms) { return mFifo.getNext(ms); }
      void internalProcess(std::unique_ptr<Message> msg);
      bool messageAvailable(void) { return mFifo.messageAvailable(); }

      void applyToAllClientSubscriptions(ClientSubscriptionFunctor*);
      void applyToAllServerSubscriptions(ServerSubscriptionFunctor*);

      void endAllServerSubscriptions(TerminateReason reason = Deactivated);
      void endAllServerPublications();

      /// Note:  Implementations of Postable must delete the message passed via post
      void registerForConnectionTermination(Postable*);
      void unRegisterForConnectionTermination(Postable*);

      // The DialogEventStateManager is returned so that the client can query it for
      // the current set of active dialogs (useful when accepting a dialog event subscription).
      // The caller is responsible for deleting the DialogEventStateManager
      // at the same time it deletes other handlers when DUM is destroyed.
      DialogEventStateManager* createDialogEventStateManager(DialogEventHandler* handler);

      void setAdvertisedCapabilities(SipMessage& msg, const std::shared_ptr<UserProfile>& userProfile);

   protected:
      virtual void onAllHandlesDestroyed();      
      //TransactionUser virtuals
      virtual const Data& name() const;
      friend class DumThread;

      DumFeatureChain::FeatureList mIncomingFeatureList;
      DumFeatureChain::FeatureList mOutgoingFeatureList;
      
      std::shared_ptr<DumFeature> mOutgoingMessageInterceptor;

      typedef std::map<Data, DumFeatureChain*> FeatureChainMap;
      FeatureChainMap mIncomingFeatureChainMap;
      FeatureChainMap mOutgoingFeatureChainMap;
  
   private:     
      friend class Dialog;
      friend class DialogSet;

      friend class ClientInviteSession;
      friend class ClientOutOfDialogReq;
      friend class ClientPublication;
      friend class ClientRegistration;
      friend class ClientSubscription;
      friend class InviteSession;
      friend class ServerInviteSession;
      friend class ServerOutOfDialogReq;
      friend class ServerPublication;
      friend class ServerRegistration;
      friend class ServerSubscription;
      friend class BaseUsage;
      friend class ClientPagerMessage;
      friend class ServerPagerMessage;
      friend class KeepAliveAssociation;
      friend class NetworkAssociation;

      friend class MergedRequestRemovalCommand;
      friend class TargetCommand::Target;

      class IncomingTarget : public TargetCommand::Target
      {
         public:
            IncomingTarget(DialogUsageManager& dum) : TargetCommand::Target(dum) 
            {
            }

            virtual void post(std::unique_ptr<Message> msg)
            {
               mDum.incomingProcess(std::move(msg));
            }
      };
      
      class OutgoingTarget : public TargetCommand::Target
      {
         public:
            OutgoingTarget(DialogUsageManager& dum) : TargetCommand::Target(dum) 
            {
            }

            virtual void post(std::unique_ptr<Message> msg)
            {
               mDum.outgoingProcess(std::move(msg));
            }
      };

      DialogSet* makeUacDialogSet(BaseCreator* creator, AppDialogSet* appDs);
      std::shared_ptr<SipMessage> makeNewSession(BaseCreator* creator, AppDialogSet* appDs);

      // makes a proto response to a request
      void makeResponse(SipMessage& response, 
                        const SipMessage& request, 
                        int responseCode, 
                        const Data& reason = Data::Empty) const;
      // May call a callback to let the app adorn
      void sendResponse(const SipMessage& response);

      void sendUsingOutboundIfAppropriate(UserProfile& userProfile, std::unique_ptr<SipMessage> msg);

      void addTimer(DumTimeout::Type type,
                    unsigned long durationSeconds,
                    BaseUsageHandle target, 
                    unsigned int seq, 
                    unsigned int altseq=0);

      void addTimerMs(DumTimeout::Type type,
                        unsigned long duration,
                        BaseUsageHandle target, 
                        unsigned int seq, 
                        unsigned int altseq=0,
                        const Data &transactionId = Data::Empty);

      Dialog& findOrCreateDialog(const SipMessage* msg);
      Dialog* findDialog(const DialogId& id);
      DialogSet* findDialogSet(const DialogSetId& id);
      
      // return 0, if no matching BaseCreator
      BaseCreator* findCreator(const DialogId& id);

      void processRequest(const SipMessage& request);
      void processResponse(const SipMessage& response);
      bool validateRequestURI(const SipMessage& request);
      bool validateRequiredOptions(const SipMessage& request);
      bool validateContent(const SipMessage& request);
      bool validateAccept(const SipMessage& request);
      bool validateTo(const SipMessage& request);
      bool validate100RelSupport(const SipMessage& request);
      
      bool mergeRequest(const SipMessage& request);

      void processPublish(const SipMessage& publish);

      void removeDialogSet(const DialogSetId& );      

      bool checkEventPackage(const SipMessage& request);

      bool queueForIdentityCheck(SipMessage* msg);
      void processIdentityCheckResponse(const HttpGetMessage& msg);

      void incomingProcess(std::unique_ptr<Message> msg);
      void outgoingProcess(std::unique_ptr<Message> msg);
      void processExternalMessage(ExternalMessageBase* externalMessage);

      // For delayed delete of a Usage
      void destroy(const BaseUsage* usage);
      void destroy(DialogSet*);
      void destroy(Dialog*);

      void requestMergedRequestRemoval(const MergedRequestKey&);
      void removeMergedRequest(const MergedRequestKey&);

      typedef std::set<MergedRequestKey> MergedRequests;
      MergedRequests mMergedRequests;
            
      typedef std::unordered_map<Data, DialogSet*> CancelMap;
      CancelMap mCancelMap;
      
      typedef HashMap<DialogSetId, DialogSet*> DialogSetMap;
      DialogSetMap mDialogSetMap;

      std::shared_ptr<MasterProfile> mMasterProfile;
      std::shared_ptr<UserProfile> mMasterUserProfile;
      std::unique_ptr<RedirectManager>   mRedirectManager;
      std::unique_ptr<ClientAuthManager> mClientAuthManager;
      //std::unique_ptr<ServerAuthManager> mServerAuthManager;  
    
      InviteSessionHandler* mInviteSessionHandler;
      ClientRegistrationHandler* mClientRegistrationHandler;
      ServerRegistrationHandler* mServerRegistrationHandler;      
      RedirectHandler* mRedirectHandler;
      DialogSetHandler* mDialogSetHandler;      
      RequestValidationHandler* mRequestValidationHandler;

      RegistrationPersistenceManager *mRegistrationPersistenceManager;
      PublicationPersistenceManager *mPublicationPersistenceManager;

      OutOfDialogHandler* getOutOfDialogHandler(MethodTypes type);

      std::map<Data, ClientSubscriptionHandler*> mClientSubscriptionHandlers;
      std::map<Data, ServerSubscriptionHandler*> mServerSubscriptionHandlers;
      std::map<Data, ClientPublicationHandler*> mClientPublicationHandlers;
      std::map<Data, ServerPublicationHandler*> mServerPublicationHandlers;
      std::map<MethodTypes, OutOfDialogHandler*> mOutOfDialogHandlers;
      std::unique_ptr<KeepAliveManager> mKeepAliveManager;
      bool mIsDefaultServerReferHandler;

      ClientPagerMessageHandler* mClientPagerMessageHandler;
      ServerPagerMessageHandler* mServerPagerMessageHandler;
      std::vector<ExternalMessageHandler*> mExternalMessageHandlers;

      // a pointer because we'll only initialize if we add a
      // server subscription handler for the 'dialog' event...
      DialogEventStateManager* mDialogEventStateManager;

      std::unique_ptr<AppDialogSetFactory> mAppDialogSetFactory;

      SipStack& mStack;
      DumShutdownHandler* mDumShutdownHandler;
      typedef enum 
      {
         Running,
         ShutdownRequested, // while ending usages
         RemovingTransactionUser, // while removing TU from stack
         Shutdown,  // after TU has been removed from stack
         Destroying // while calling destructor
      } ShutdownState;
      ShutdownState mShutdownState;

      // from ETag -> ServerPublication
      typedef std::map<Data, ServerPublication*> ServerPublications;
      ServerPublications mServerPublications;
      typedef std::map<Data, SipMessage*> RequiresCerts;
      RequiresCerts mRequiresCerts;      
      // from Event-Type+document-aor -> ServerSubscription
      // Managed by ServerSubscription
      typedef std::multimap<Data, ServerSubscription*> ServerSubscriptions;
      ServerSubscriptions mServerSubscriptions;

      IncomingTarget* mIncomingTarget;
      OutgoingTarget* mOutgoingTarget;
      ThreadIf::TlsKey mThreadDebugKey;
      ThreadIf::TlsKey mHiddenThreadDebugKey;

      EventDispatcher<ConnectionTerminated> mConnectionTerminatedEventDispatcher;
};

}

#endif

/* ====================================================================
 * The Vovida Software License, Version 1.0 
 * 
 * Copyright (c) 2000 Vovida Networks, Inc.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * 3. The names "VOCAL", "Vovida Open Communication Application Library",
 *    and "Vovida Open Communication Application Library (VOCAL)" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact vocal@vovida.org.
 *
 * 4. Products derived from this software may not be called "VOCAL", nor
 *    may "VOCAL" appear in their name, without prior written
 *    permission of Vovida Networks, Inc.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL VOVIDA
 * NETWORKS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT DAMAGES
 * IN EXCESS OF $1,000, NOR FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 * ====================================================================
 * 
 * This software consists of voluntary contributions made by Vovida
 * Networks, Inc. and many individuals on behalf of Vovida Networks,
 * Inc.  For more information on Vovida Networks, Inc., please see
 * <http://www.vovida.org/>.
 *
 */
