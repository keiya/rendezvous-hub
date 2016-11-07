FROM ruby:2.3

ADD . /app
WORKDIR /app
RUN bundle install
