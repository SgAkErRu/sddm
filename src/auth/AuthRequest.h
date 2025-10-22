/*
 * Qt Authentication library
 * Copyright (c) 2013 Martin Bříza <mbriza@redhat.com>
 * Copyright (c) 2018 Thomas Höhn <thomas_hoehn@gmx.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */

#ifndef REQUEST_H
#define REQUEST_H

#include <QtCore/QObject>

#include <QtQml/QQmlListProperty>

#include <AuthPrompt.h>

namespace SDDM {
    class Auth;
    class AuthPrompt;
    class Request;
    /**
    * \brief
    * AuthRequest is the main class for tracking requests from the underlying auth stack
    *
    * \section description
    * Typically, when logging in, you'll receive a list containing one or two fields:
    *
    *  * First one for the username (if you didn't provide it before);
    *    hidden = false, type = LOGIN_USER, message = whatever the stack provides
    *
    *  * Second one for the user's password
    *    hidden = true, type = LOGIN_PASSWORD, message = whatever the stack provides
    *
    * It's up to you to fill the \ref AuthPrompt::response property.
    * When all the fields are filled to your satisfaction, just trigger the \ref done
    * slot and the response will go back to the authenticator.
    *
    * \todo Decide if it's sane to use the info messages from PAM or to somehow parse them
    * and make the password changing message into a Request::Type of some kind
    */
    class AuthRequest : public QObject {
        Q_OBJECT
        Q_PROPERTY(QQmlListProperty<AuthPrompt> prompts READ promptsDecl NOTIFY promptsChanged)
        Q_PROPERTY(bool finishAutomatically READ finishAutomatically WRITE setFinishAutomatically NOTIFY finishAutomaticallyChanged)
    public:
        /**
        * @return list of the contained prompts
        */
        QList<AuthPrompt*> prompts();
        /**
        * For QML apps
        * @return list of the contained prompts
        */
        QQmlListProperty<AuthPrompt> promptsDecl();
        /**
          * @brief Write responses into request for pam conv(),
          * for AuthPrompt::LOGIN_USER,LOGIN_PASSWORD,CHANGE_PASSWORD
          * @return true if response was set
          */
        Q_INVOKABLE bool setLoginResponse(const QString &username, const QString &password);
        Q_INVOKABLE bool setChangeResponse(const QString &password);

        static AuthRequest *empty();

        bool finishAutomatically();
        /**
         * @brief Trigger slot done() automaticly when all AuthPrompt responses (user passwords) are set.
         * @param value  if true done() automaticly called, if false user calls done() after specifying all responses
         */
        void setFinishAutomatically(bool value);
        /**
         * @brief find prompt with specified type
         * @param type \ref AuthPrompt::Type
         * @return pointer to prompt of that type
         */
        AuthPrompt *findPrompt(AuthPrompt::Type type) const;

    public Q_SLOTS:
        /**
        * Call this slot when all prompts has been filled to your satisfaction
        */
        void done();
        /**
        * Call this slot when user canceled PAM conversation
        */
        void cancel();
    Q_SIGNALS:
        /**
        * Emitted when \ref done was called
        */
        void finished();
        void canceled();
        void finishAutomaticallyChanged();
        void promptsChanged();
    private:
        AuthRequest(Auth *parent);
        void setRequest(const Request *request = nullptr);
        Request request() const;
        friend class Auth;
        class Private;
        Private *d { nullptr };
    };
}

#endif //REQUEST_H
