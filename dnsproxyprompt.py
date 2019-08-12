from cmd import Cmd

class DNSProxyPrompt(Cmd):
    '''
        Template dictionary containing { cidr: "Template" }
    '''
    _templates = {}

    def SetTemplate(self, cidr, name):
        print(f'Setting template {name} to cidr: {cidr}.')
        self._templates[cidr] = name

    def do_if(self, args):
        if len(args) == 0:
            raise SyntaxError('No conditions set for if')
        else:
            args = args.split(':')
            print(args)
            print(self._templates)
            if eval(args[0]):
                try:
                    eval(f'self.{args[1].strip()}')
                except Exception as E:
                    print(E)
        
        func = "func"
        print(f'Using {func}')

    def do_quit(self, args):
        """Quits the program."""
        print('Quitting.')
        raise SystemExit
    

if __name__ == '__main__':
    prompt = DNSProxyPrompt()
    prompt.prompt = '> '
    prompt.cmdloop('Starting prompt...')