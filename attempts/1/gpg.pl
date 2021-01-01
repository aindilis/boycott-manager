%% https://www.gnupg.org/gph/en/manual/x135.html

:- use_module(library(regex)).

shellQuote(Document,Document).

getSignature(Document,SignedDocument) :-
	atomic_list_concat([Document,'.sig'],'',SignedDocument).

getDocument(SignedDocument,NewDocument) :-
	re_split(".sig",SignedDocument,Document,[]).

prepareDocuments(Document,SignedDocument,QDocument,QSignedDocument) :-
	(   nonvar(SignedDocument) -> true ; getSignature(Document,SignedDocument) ),
	shellQuote(Document,QDocument),
	shellQuote(SignedDocument,QSignedDocument).

sign(Document,SignedDocument) :-
	prepareDocuments(Document,SignedDocument,QDocument,QSignedDocument),
	atomic_list_concat(['gpg --output',QSignedDocument,'--sign',QDocument],' ',SignCommand),
	view([signCommand,SignCommand]).

clearSign(Document,SignedDocument) :-
	prepareDocuments(Document,SignedDocument,QDocument,QSignedDocument),
	atomic_list_concat(['gpg --output',QSignedDocument,'--clearsign',QDocument],' ',SignCommand),
	view([signCommand,SignCommand]).

unsign(SignedDocument,NewDocument) :-
	shellQuote(SignedDocument,QSignedDocument),
	(   nonvar(NewDocument) -> true ; getDocument(SignedDocument,NewDocument) ),
	shellQuote(NewDocument,QNewDocument),
 	atomic_list_concat(['gpg --output',QNewDocument,'--decrypt',QSignedDocument],' ',UnsignCommand),
	view([unsignCommand,UnsignCommand]).

detachedSign(Document,SignedDocument) :-
	prepareDocuments(Document,SignedDocument,QDocument,QSignedDocument),
	atomic_list_concat(['gpg --output',QSignedDocument,'--detach-sig',QDocument],' ',SignCommand),
	view([signCommand,SignCommand]).

verify(Document,SignedDocument) :-
	prepareDocuments(Document,SignedDocument,QDocument,QSignedDocument),
	atomic_list_concat(['gpg --verify',QSignedDocument,QDocument],' ',VerifyCommand),
	view([verifyCommand,VerifyCommand]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                %% SEE INSTEAD library(crypto)

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
