#include "sample.h"
#include <iostream>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/named_values.h>
#include <libecap/host/host.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>

namespace Adapter { // not required, but adds clarity

using libecap::size_type;

class Service: public libecap::adapter::Service {
	public:
		// About
		virtual std::string uri() const; // unique across all vendors
		virtual std::string tag() const; // changes with version and config
		virtual void describe(std::ostream &os) const; // free-format info

		// Configuration
		virtual void configure(const libecap::Options &cfg);
		virtual void reconfigure(const libecap::Options &cfg);
		void setOne(const libecap::Name &name, const libecap::Area &valArea);

		// Lifecycle
		virtual void start(); // expect makeXaction() calls
		virtual void stop(); // no more makeXaction() calls until start()
		virtual void retire(); // no more makeXaction() calls

		// Scope (XXX: this may be changed to look at the whole header)
		virtual bool wantsUrl(const char *url) const;

		// Work
		virtual libecap::adapter::Xaction *makeXaction(libecap::host::Xaction *hostx);

	public:
		// Configuration storage
		std::string victim; // the text we want to replace
		std::string replacement; // what the replace the victim with

	protected:
		void setVictim(const std::string &value);
};


// Calls Service::setOne() for each host-provided configuration option.
// See Service::configure().
class Cfgtor: public libecap::NamedValueVisitor {
	public:
		Cfgtor(Service &aSvc): svc(aSvc) {}
		virtual void visit(const libecap::Name &name, const libecap::Area &value) {
			svc.setOne(name, value);
		}
		Service &svc;
};


class Xaction: public libecap::adapter::Xaction {
	public:
		Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
		virtual ~Xaction();

		// meta-information for the host transaction
		virtual const libecap::Area option(const libecap::Name &name) const;
		virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

		// lifecycle
		virtual void start();
		virtual void stop();

		// adapted body transmission control
		virtual void abDiscard();
		virtual void abMake();
		virtual void abMakeMore();
		virtual void abStopMaking();

		// adapted body content extraction and consumption
		virtual libecap::Area abContent(size_type offset, size_type size);
		virtual void abContentShift(size_type size);

		// virgin body state notification
		virtual void noteVbContentDone(bool atEnd);
		virtual void noteVbContentAvailable();

		// libecap::Callable API, via libecap::host::Xaction
		virtual bool callable() const;

	protected:
		void adaptContent(std::string &chunk) const; // converts vb to ab
		void stopVb(); // stops receiving vb (if we are receiving it)
		libecap::host::Xaction *lastHostCall(); // clears hostx

	private:
		libecap::shared_ptr<const Service> service; // configuration access
		libecap::host::Xaction *hostx; // Host transaction rep

		std::string buffer; // for content adaptation

		typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
		OperationState receivingVb;
		OperationState sendingAb;
};

static const std::string CfgErrorPrefix =
	"Modifying Adapter: configuration error: ";

} // namespace Adapter

std::string Adapter::Service::uri() const {
	return "ecap://e-cap.org/ecap/services/sample/modifying";
}

std::string Adapter::Service::tag() const {
	return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const {
	os << "A modifying adapter from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void Adapter::Service::configure(const libecap::Options &cfg) {
	Cfgtor cfgtor(*this);
	cfg.visitEachOption(cfgtor);

	// check for post-configuration errors and inconsistencies

	if (victim.empty()) {
		throw libecap::TextException(CfgErrorPrefix +
			"victim value is not set");
	}
}

void Adapter::Service::reconfigure(const libecap::Options &cfg) {
	victim.clear();
	replacement.clear();
	configure(cfg);
}

void Adapter::Service::setOne(const libecap::Name &name, const libecap::Area &valArea) {
	const std::string value = valArea.toString();
	if (name == "victim")
		setVictim(value);
	else
	if (name == "replacement")
		replacement = value; // no checks needed, even an empty value is OK
	else
	if (name.assignedHostId())
		; // skip host-standard options we do not know or care about
	else
		throw libecap::TextException(CfgErrorPrefix +
			"unsupported configuration parameter: " + name.image());
}

void Adapter::Service::setVictim(const std::string &value) {
	if (value.empty()) {
		throw libecap::TextException(CfgErrorPrefix +
			"empty victim value is not allowed");
	}
	victim = value;
}

void Adapter::Service::start() {
	libecap::adapter::Service::start();
	// custom code would go here, but this service does not have one
}

void Adapter::Service::stop() {
	// custom code would go here, but this service does not have one
	libecap::adapter::Service::stop();
}

void Adapter::Service::retire() {
	// custom code would go here, but this service does not have one
	libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(const char *url) const {
	return true; // no-op is applied to all messages
}

libecap::adapter::Xaction *Adapter::Service::makeXaction(libecap::host::Xaction *hostx) {
	return new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self),
		hostx);
}


Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,
	libecap::host::Xaction *x):
	service(aService),
	hostx(x),
	receivingVb(opUndecided), sendingAb(opUndecided) {
}

Adapter::Xaction::~Xaction() {
	if (libecap::host::Xaction *x = hostx) {
		hostx = 0;
		x->adaptationAborted();
	}
}

const libecap::Area Adapter::Xaction::option(const libecap::Name &) const {
	return libecap::Area(); // this transaction has no meta-information
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &) const {
	// this transaction has no meta-information to pass to the visitor
}

void Adapter::Xaction::start() {
	Must(hostx);
	if (hostx->virgin().body()) {
		receivingVb = opOn;
		hostx->vbMake(); // ask host to supply virgin body
	} else {
		// we are not interested in vb if there is not one
		receivingVb = opNever;
	}

	/* adapt message header */

	libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
	Must(adapted != 0);

	// delete ContentLength header because we may change the length
	// unknown length may have performance implications for the host
	adapted->header().removeAny(libecap::headerContentLength);

	// add a custom header
	static const libecap::Name name("X-Ecap");
	const libecap::Header::Value value =
		libecap::Area::FromTempString(libecap::MyHost().uri());
	adapted->header().add(name, value);

	if (!adapted->body()) {
		sendingAb = opNever; // there is nothing to send
		lastHostCall()->useAdapted(adapted);
	} else {
		hostx->useAdapted(adapted);
	}
}

void Adapter::Xaction::stop() {
	hostx = 0;
	// the caller will delete
}

void Adapter::Xaction::abDiscard()
{
	Must(sendingAb == opUndecided); // have not started yet
	sendingAb = opNever;
	// we do not need more vb if the host is not interested in ab
	stopVb();
}

void Adapter::Xaction::abMake()
{
	Must(sendingAb == opUndecided); // have not yet started or decided not to send
	Must(hostx->virgin().body()); // that is our only source of ab content

	// we are or were receiving vb
	Must(receivingVb == opOn || receivingVb == opComplete);
	
	sendingAb = opOn;
	if (!buffer.empty())
		hostx->noteAbContentAvailable();
}

void Adapter::Xaction::abMakeMore()
{
	Must(receivingVb == opOn); // a precondition for receiving more vb
	hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking()
{
	sendingAb = opComplete;
	// we do not need more vb if the host is not interested in more ab
	stopVb();
}


libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size) {
	Must(sendingAb == opOn || sendingAb == opComplete);
	return libecap::Area::FromTempString(buffer.substr(offset, size));
}

void Adapter::Xaction::abContentShift(size_type size) {
	Must(sendingAb == opOn || sendingAb == opComplete);
	buffer.erase(0, size);
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
	Must(receivingVb == opOn);
	receivingVb = opComplete;
	if (sendingAb == opOn) {
		hostx->noteAbContentDone(atEnd);
		sendingAb = opComplete;
	}
}

void Adapter::Xaction::noteVbContentAvailable()
{
	Must(receivingVb == opOn);

	const libecap::Area vb = hostx->vbContent(0, libecap::nsize); // get all vb
	std::string chunk = vb.toString(); // expensive, but simple
	hostx->vbContentShift(vb.size); // we have a copy; do not need vb any more
	adaptContent(chunk);
	buffer += chunk; // buffer what we got

	if (sendingAb == opOn)
		hostx->noteAbContentAvailable();
}

void Adapter::Xaction::adaptContent(std::string &chunk) const {
	// this is oversimplified; production code should worry about arbitrary
	// chunk boundaries, content encodings, service reconfigurations, etc.

	const std::string &victim = service->victim;
	const std::string &replacement = service->replacement;

	std::string::size_type pos = 0;
	while ((pos = chunk.find(victim, pos)) != std::string::npos) {
		chunk.replace(pos, victim.length(), replacement);
		pos += replacement.size();
	}
}

bool Adapter::Xaction::callable() const {
	return hostx != 0; // no point to call us if we are done
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
	if (receivingVb == opOn) {
		hostx->vbStopMaking();
		receivingVb = opComplete;
	} else {
		// we already got the entire body or refused it earlier
		Must(receivingVb != opUndecided);
	}
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall() {
	libecap::host::Xaction *x = hostx;
	Must(x);
	hostx = 0;
	return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered = (libecap::RegisterService(new Adapter::Service), true);
