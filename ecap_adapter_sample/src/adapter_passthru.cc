#include "sample.h"
#include <iostream>
#include <libecap/common/message.h>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
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

		// Lifecycle
		virtual void start(); // expect makeXaction() calls
		virtual void stop(); // no more makeXaction() calls until start()
		virtual void retire(); // no more makeXaction() calls

		// Scope (XXX: this may be changed to look at the whole header)
		virtual bool wantsUrl(const char *url) const;

		// Work
		virtual libecap::adapter::Xaction *makeXaction(libecap::host::Xaction *hostx);
};


class Xaction: public libecap::adapter::Xaction {
	public:
		Xaction(libecap::host::Xaction *x);
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
		libecap::host::Xaction *lastHostCall(); // clears hostx

	private:
		libecap::host::Xaction *hostx; // Host transaction rep

		typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
		OperationState receivingVb;
		OperationState sendingAb;
};

} // namespace Adapter

std::string Adapter::Service::uri() const {
	return "ecap://e-cap.org/ecap/services/sample/passthru";
}

std::string Adapter::Service::tag() const {
	return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const {
	os << "A passthru adapter from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void Adapter::Service::configure(const libecap::Options &) {
	// this service is not configurable
}

void Adapter::Service::reconfigure(const libecap::Options &) {
	// this service is not configurable
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
	return new Adapter::Xaction(hostx);
}


Adapter::Xaction::Xaction(libecap::host::Xaction *x): hostx(x),
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
	// TODO: libecap should probably supply a global LastCall() of sorts
	// to clear hostx member and then call the host transaction one last time
	Must(hostx);
	if (hostx->virgin().body()) {
		receivingVb = opOn;
		hostx->vbMake(); // ask host to supply virgin body
	} else {
		receivingVb = opNever;
	}

	libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
	Must(adapted != 0);
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
}

void Adapter::Xaction::abMake()
{
	Must(sendingAb == opUndecided); // have not yet started or decided not to send
	Must(hostx->virgin().body()); // that is our only source of ab content

	// we are or were receiving vb
	Must(receivingVb == opOn || receivingVb == opComplete);
	
	sendingAb = opOn;
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
	// we may still continue receiving
}


libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size)
{
	Must(sendingAb == opOn);
	return hostx->vbContent(offset, size);
}

void Adapter::Xaction::abContentShift(size_type size)
{
	Must(sendingAb == opOn);
	hostx->vbContentShift(size);
}


void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
	Must(receivingVb == opOn);
	receivingVb = opComplete;
	hostx->noteAbContentDone(atEnd);
}

void Adapter::Xaction::noteVbContentAvailable()
{
	Must(receivingVb == opOn);
	if (sendingAb == opOn)
		hostx->noteAbContentAvailable();
}


bool Adapter::Xaction::callable() const {
	return hostx != 0; // no point to call us if we are done
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


