FROM ruby:2.4

ADD . /app
WORKDIR /app
RUN bundle install
