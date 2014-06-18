package MooseX::Meta::Method::Role::Authorized;
use  MooseX::Meta::Method::Role::Authorized::Meta::Role;
# use Moose::Util::TypeConstraints;
# use aliased 'MooseX::Meta::Method::Role::Authorized::HasRoles';

has requires =>
  ( is => 'ro',
    isa => 'HashRef',
    default => sub { [] } );

# my $default_verifier = HasRoles->new();

# has verifier =>
  # ( is => 'ro',
    # isa => duck_type(['authorized_do']),
    # default => sub { $default_verifier } );
around wrap => sub {
    my ($wrap, $method, $code, %options) = @_;
 
    my $requires = $options{requires};
     use Data::Dumper;
 #    warn("wrap=".Dumper($requires));
    # warn("x=".((exists($requires->{requires}) and ref($requires->{requires}) eq 'ARRAY')));
    # warn("x=".(((exists($requires->{requires}) and ref($requires->{requires}) eq 'ARRAY')) or
              # ((exists($requires->{one_of}) and ref($requires->{one_of}) eq 'ARRAY'))));
    
    die "requires hash-ref must have either a 'required' or 'one_of' or both key that points to an array-ref of Roles!"
      unless (((exists($requires->{required}) and ref($requires->{required}) eq 'ARRAY')) or
              ((exists($requires->{one_of}) and ref($requires->{one_of}) eq 'ARRAY')));
    
    my $meth_obj;
    $meth_obj = $method->$wrap
      (
       sub {
           $meth_obj->authorized_do($meth_obj, $code, @_)
       },
       %options
      );
     
    return $meth_obj;
};

sub authorized_do {
    my $self = shift;
    my $method = shift;
    my $requires = $method->requires;
    my $code = shift;
 
    my ($instance) = @_;
    use Data::Dumper;
    
#    warn(Dumper($requires));
    foreach my $key (keys($requires)){
      my $author_sub = '_authorize_'.$key;
      next
        unless ($self->can($author_sub));
      $self->$author_sub($requires->{$key},$instance);
      
      
    }
     $code->(@_);
       # warn("here someplce roles=".Dumper($roles ));
    #die "You Die Now GI!!" if !Moose::Util::does_role($instance,$roles->[0]);
    
    #just to see if this works
}

sub _authorize_required {
  my $self    = shift;
  my ($roles,$instance) = @_;
  
  foreach my $role (@{$roles}){
      die "You Die Now GI!!" 
      if !Moose::Util::does_role($instance,$role);
 }
}

sub _authorize_one_of {
  my $self    = shift;
  my ($roles,$instance) = @_;
  
  foreach my $role (@{$roles}){
    return 1
      if (Moose::Util::does_role($instance,$role));

  }

  die "You Die Now GI!!";

}
1;

__END__

=head1 NAME

MooseX::Meta::Method::Authorized - Authorization in method calls

=head1 DESCRIPTION

This trait provides support for verifying authorization before calling
a method.

=head1 ATTRIBUTES

=over

=item requires

This attribute is an array reference with the values that are going to
be used by the verifier when checking this invocation.

=item verifier

This is the object/class on which the "authorized_do" method is going
to be invoked. This is the object responsible for doing the actual
verification. It is invoked as:

  $verifier->authorized_do($meth_obj, $code, @_)

It is expected that this method should die if the authorization is not
stablished.

The default value for this attribute is
L<MooseX::Meta::Method::Authorized::CheckRoles>, which will get the
current user by calling the "user" method and list the roles given to
that user by invoking the "roles" method.

=back

=head1 METHOD

=over

=item wrap

This role overrides wrap so that the actual method is only invoked
after the authorization being checked.

=back

=head1 SEE ALSO

L<MooseX::AuthorizedMethods>, L<Class::MOP::Method>

=head1 AUTHORS

Daniel Ruoso E<lt>daniel@ruoso.comE<gt>

With help from rafl and doy from #moose.

=head1 COPYRIGHT AND LICENSE

Copyright 2010 by Daniel Ruoso et al

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
